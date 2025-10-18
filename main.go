package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/crypto/bcrypt"
)

// ==========================================================
// --- 1. 配置与结构体定义 (现代化架构) ---
// ==========================================================

const ConfigFile = "ws_config.json"
const logBufferSize = 200

type Settings struct {
	ListenAddrs                  []string `json:"listen_addrs"`
	AdminListenAddr              string   `json:"admin_listen_addr"`
	DefaultTargetHost            string   `json:"default_target_host"`
	DefaultTargetPort            int      `json:"default_target_port"`
	BufferSize                   int      `json:"buffer_size"`
	HandshakePeek                int      `json:"handshake_peek"`
	HandshakeTimeout             int      `json:"handshake_timeout"`
	IdleTimeout                  int      `json:"idle_timeout"`
	MaxConns                     int      `json:"max_conns"`
	EnableAuth                   bool     `json:"enable_auth"`
	UAKeywordWS                  string   `json:"ua_keyword_ws"`
	UAKeywordProbe               string   `json:"ua_keyword_probe"`
	CertFile                     string   `json:"cert_file"`
	KeyFile                      string   `json:"key_file"`
	AllowSimultaneousConnections bool     `json:"allow_simultaneous_connections"`
	IPWhitelist                  []string `json:"ip_whitelist"`
	IPBlacklist                  []string `json:"ip_blacklist"`
	EnableIPWhitelist            bool     `json:"enable_ip_whitelist"`
	EnableIPBlacklist            bool     `json:"enable_ip_blacklist"`
}

type DeviceInfo struct {
	FriendlyName string `json:"friendly_name"`
	Expiry       string `json:"expiry"`
	LimitGB      int    `json:"limit_gb"`
	UsedBytes    int64  `json:"used_bytes"`
	MaxSessions  int    `json:"max_sessions"`
	Enabled      bool   `json:"enabled"`
}

type Config struct {
	Settings  Settings              `json:"settings"`
	Accounts  map[string]string     `json:"accounts"`
	DeviceIDs map[string]DeviceInfo `json:"device_ids"`
	lock      sync.RWMutex          `json:"-"`
}

type Proxy struct {
	cfg                 *Config
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	startTime           time.Time
	conns               sync.Map
	deviceUsage         sync.Map
	tlsConfig           *tls.Config
	connSemaphore       chan struct{}
	listeners           []net.Listener
	globalBytesSent     int64
	globalBytesReceived int64
	logBuffer           *RingBuffer
	systemStatus        SystemStatus
	statusMutex         sync.RWMutex
}

type ActiveConnInfo struct {
	mu                     sync.RWMutex
	conn                   net.Conn
	connKey                string
	ip                     string
	status                 string
	protocol               string
	firstConnection        time.Time
	lastActive             int64
	bytesSent              int64
	bytesReceived          int64
	cancel                 context.CancelFunc
	deviceID               string
	credential             string
	currentSpeedBps        float64
	lastSpeedUpdateTime    time.Time
	lastTotalBytesForSpeed int64
}

type SystemStatus struct {
	Uptime        string  `json:"uptime"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemPercent    float64 `json:"mem_percent"`
	NumGoroutine  int     `json:"num_goroutine"`
	ActiveConns   int     `json:"active_conns"`
	BytesSent     string  `json:"bytes_sent"`
	BytesReceived string  `json:"bytes_received"`
}

var bufferPool sync.Pool

func initBufferPool(size int) {
	if size <= 0 {
		size = 32 * 1024
	}
	bufferPool = sync.Pool{New: func() interface{} { return make([]byte, size) }}
}
func getBuf(size int) []byte {
	b := bufferPool.Get().([]byte)
	if cap(b) < size {
		return make([]byte, size)
	}
	return b[:size]
}
func putBuf(b []byte) { bufferPool.Put(b) }

type RingBuffer struct {
	mu     sync.RWMutex
	buffer []string
	head   int
}

func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{buffer: make([]string, capacity)}
}
func (rb *RingBuffer) Add(msg string) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	logLine := fmt.Sprintf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), msg)
	rb.buffer[rb.head] = logLine
	rb.head = (rb.head + 1) % len(rb.buffer)
	fmt.Println(logLine)
}
func (rb *RingBuffer) GetLogs() []string {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	var logs []string
	for i := 0; i < len(rb.buffer); i++ {
		idx := (rb.head + i) % len(rb.buffer)
		if rb.buffer[idx] != "" {
			logs = append(logs, rb.buffer[idx])
		}
	}
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}
	return logs
}

func (p *Proxy) Print(format string, v ...interface{}) {
	p.logBuffer.Add(fmt.Sprintf(format, v...))
}

func defaultConfig() *Config {
	return &Config{
		Settings: Settings{
			ListenAddrs:                  []string{"0.0.0.0:80", "0.0.0.0:443"},
			AdminListenAddr:              "127.0.0.1:9090",
			DefaultTargetHost:            "127.0.0.1",
			DefaultTargetPort:            22,
			BufferSize:                   32768,
			HandshakePeek:                1024,
			HandshakeTimeout:             10,
			IdleTimeout:                  300,
			MaxConns:                     4096,
			EnableAuth:                   true,
			UAKeywordWS:                  "26.4.0",
			UAKeywordProbe:               "1.0",
			CertFile:                     "cert.pem",
			KeyFile:                      "key.pem",
			AllowSimultaneousConnections: false,
		},
		Accounts:  map[string]string{"admin": "admin"},
		DeviceIDs: make(map[string]DeviceInfo),
	}
}

func (c *Config) SaveAtomic() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := ConfigFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, ConfigFile)
}

func LoadConfig() (*Config, error) {
	if _, err := os.Stat(ConfigFile); os.IsNotExist(err) {
		cfg := defaultConfig()
		if err := cfg.SaveAtomic(); err != nil {
			return nil, err
		}
		return cfg, nil
	}
	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
// ==========================================================
// --- 2. Proxy 核心实现 (生命周期, 监听, 协议嗅探) ---
// ==========================================================

func NewProxy(cfg *Config) (*Proxy, error) {
	ctx, cancel := context.WithCancel(context.Background())

	var tlsConfig *tls.Config
	if cfg.Settings.CertFile != "" && cfg.Settings.KeyFile != "" {
		if _, err := os.Stat(cfg.Settings.CertFile); err == nil {
			if _, err := os.Stat(cfg.Settings.KeyFile); err == nil {
				cert, err := tls.LoadX509KeyPair(cfg.Settings.CertFile, cfg.Settings.KeyFile)
				if err != nil {
					log.Printf("[!] Cert warning: %v. TLS/WSS will not be available.", err)
				} else {
					tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
				}
			} else {
				log.Printf("[!] TLS Key file '%s' not found. TLS/WSS will not be available.", cfg.Settings.KeyFile)
			}
		} else {
			log.Printf("[!] TLS Cert file '%s' not found. TLS/WSS will not be available.", cfg.Settings.CertFile)
		}
	}

	p := &Proxy{
		cfg:           cfg,
		ctx:           ctx,
		cancel:        cancel,
		startTime:     time.Now(),
		logBuffer:     NewRingBuffer(logBufferSize),
		tlsConfig:     tlsConfig,
		connSemaphore: make(chan struct{}, cfg.Settings.MaxConns),
		listeners:     make([]net.Listener, 0),
	}

	initBufferPool(p.cfg.Settings.BufferSize)
	p.initMetrics()
	return p, nil
}

func (p *Proxy) Start() error {
	if len(p.cfg.Settings.ListenAddrs) == 0 {
		return errors.New("no listen addresses configured")
	}

	for _, addr := range p.cfg.Settings.ListenAddrs {
		l, err := net.Listen("tcp4", addr)
		if err != nil {
			p.Print("[!] cannot listen on %s: %v", addr, err)
			continue
		}
		p.Print("[*] Proxy listening on %s", addr)
		p.listeners = append(p.listeners, l)

		p.wg.Add(1)
		go p.acceptLoop(l)
	}

	if len(p.listeners) == 0 {
		return errors.New("no valid listeners started")
	}

	go p.runPeriodicTasks()
	return nil
}

func (p *Proxy) Shutdown() {
	p.Print("[*] Shutting down server...")

	for _, l := range p.listeners {
		l.Close()
	}

	p.cancel()
	p.wg.Wait()
	p.saveDeviceUsage()
	p.Print("[*] Server gracefully stopped.")
}

func (p *Proxy) acceptLoop(l net.Listener) {
	defer p.wg.Done()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				if !strings.Contains(err.Error(), "use of closed network connection") {
					p.Print("[!] accept error on %s: %v", l.Addr().String(), err)
				}
				return
			}
		}

		if !p.acquire() {
			p.Print("[-] Rejecting connection from %s: too many connections", conn.RemoteAddr().String())
			sendHTTPErrorAndClose(conn, http.StatusServiceUnavailable, "Service Unavailable", "Too many connections")
			continue
		}

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.release()
			p.handleConnection(conn)
		}()
	}
}

func (p *Proxy) handleConnection(conn net.Conn) {
	defer conn.Close()
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	if p.cfg.Settings.EnableIPBlacklist && isIPInList(remoteIP, p.cfg.Settings.IPBlacklist) {
		p.Print("[-] Connection from blacklisted IP %s rejected.", remoteIP)
		return
	}
	if p.cfg.Settings.EnableIPWhitelist && !isIPInList(remoteIP, p.cfg.Settings.IPWhitelist) {
		p.Print("[-] Connection from non-whitelisted IP %s rejected.", remoteIP)
		return
	}

	p.Print("[+] Connection opened from %s", remoteIP)

	timeout := time.Duration(p.cfg.Settings.HandshakeTimeout) * time.Second
	conn.SetReadDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	peekedBytes, err := reader.Peek(p.cfg.Settings.HandshakePeek)
	if err != nil {
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			}
		}
		return
	}
	conn.SetReadDeadline(time.Time{})

	if isTLS(peekedBytes) {
		p.handleTLSConnection(conn, reader)
	} else if isHTTP(peekedBytes) {
		p.handleHTTPPayloadConnection(conn, reader)
	} else {
		p.handleDirectConnection(conn, reader)
	}
}

func (p *Proxy) acquire() bool {
	select {
	case p.connSemaphore <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p *Proxy) release() {
	<-p.connSemaphore
}

func isTLS(peekedBytes []byte) bool {
	return len(peekedBytes) > 5 && peekedBytes[0] == 0x16 && peekedBytes[1] == 0x03
}

func isHTTP(peekedBytes []byte) bool {
	s := string(peekedBytes)
	return strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "POST ") ||
		strings.HasPrefix(s, "PUT ") || strings.HasPrefix(s, "HEAD ") ||
		strings.HasPrefix(s, "OPTIONS ") || strings.HasPrefix(s, "DELETE ")
}
// ==========================================================
// --- 3. 协议处理器和核心转发逻辑 ---
// ==========================================================

func (p *Proxy) handleTLSConnection(conn net.Conn, reader *bufio.Reader) {
	if p.tlsConfig == nil {
		p.Print("[!] TLS connection from %s rejected: TLS not configured", conn.RemoteAddr())
		return
	}
	tlsConn := tls.Server(conn, p.tlsConfig)

	err := tlsConn.SetReadDeadline(time.Now().Add(time.Duration(p.cfg.Settings.HandshakeTimeout) * time.Second))
	if err != nil {
		p.Print("[!] Failed to set TLS handshake deadline for %s: %v", conn.RemoteAddr(), err)
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		if err != io.EOF && !strings.Contains(err.Error(), "read: connection reset by peer") {
			p.Print("[!] TLS handshake error from %s: %v", conn.RemoteAddr(), err)
		}
		return
	}
	tlsConn.SetReadDeadline(time.Time{})

	p.handleHTTPPayloadConnection(tlsConn, bufio.NewReader(tlsConn))
}

func (p *Proxy) handleHTTPPayloadConnection(conn net.Conn, reader *bufio.Reader) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	connKey := fmt.Sprintf("%s-%d", remoteIP, time.Now().UnixNano())
	_, cancel := context.WithCancel(p.ctx)
	defer cancel()

	connInfo := &ActiveConnInfo{
		conn:            conn,
		connKey:         connKey,
		ip:              remoteIP,
		protocol:        "HTTP/WSS",
		status:          "握手",
		firstConnection: time.Now(),
		lastActive:      time.Now().Unix(),
		cancel:          cancel,
	}
	p.AddActiveConn(connKey, connInfo)
	defer p.RemoveActiveConn(connKey)

	var initialData []byte
	var headersText string
	handshakeTimeout := time.Duration(p.cfg.Settings.HandshakeTimeout) * time.Second
	handshakeComplete := false

	for !handshakeComplete {
		conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		req, err := http.ReadRequest(reader)
		if err != nil {
			// ############ 修正点 1: 增加详细错误日志 ############
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				p.Print("[!] Handshake timeout for %s", remoteIP)
			} else if err != io.EOF {
				p.Print("[!] Handshake read error from %s: %v", remoteIP, err)
			}
			return
		}

		var headerBuilder strings.Builder
		req.Header.Write(&headerBuilder)
		headersText = req.Method + " " + req.RequestURI + " " + req.Proto + "\r\n" + headerBuilder.String()

		req.Body = http.MaxBytesReader(nil, req.Body, 64*1024)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			p.Print("[!] Handshake read body error from %s: %v", remoteIP, err)
			sendHTTPErrorAndClose(conn, http.StatusBadRequest, "Bad Request", "Request body too large or invalid.")
			return
		}
		req.Body.Close()
		initialData = body

		if p.cfg.Settings.EnableAuth {
			// ############ 修正点 2: 使用自定义 Header "X-Device-ID" 进行认证 ############
			credential := req.Header.Get("X-Device-ID")
			if credential == "" {
				p.Print("[!] Auth Failed: Missing 'X-Device-ID' header from %s", remoteIP)
				sendHTTPErrorAndClose(conn, http.StatusUnauthorized, "Unauthorized", "Missing Credentials")
				return
			}

			p.cfg.lock.RLock()
			deviceInfo, found := p.cfg.DeviceIDs[credential]
			p.cfg.lock.RUnlock()

			if !found {
				p.Print("[!] Auth Failed: Invalid 'X-Device-ID' [%s] from %s", credential, remoteIP)
				sendHTTPErrorAndClose(conn, http.StatusUnauthorized, "Unauthorized", "Invalid Credentials")
				return
			}
			if !deviceInfo.Enabled {
				p.Print("[!] Auth Failed: Device '%s' is disabled for %s", deviceInfo.FriendlyName, remoteIP)
				sendHTTPErrorAndClose(conn, http.StatusForbidden, "Forbidden", "账号被禁止,请联系管理员解锁")
				return
			}
			expiry, err := time.Parse("2006-01-02", deviceInfo.Expiry)
			if err != nil || time.Now().After(expiry.Add(24*time.Hour)) {
				p.Print("[!] Auth Failed: Device '%s' has expired for %s", deviceInfo.FriendlyName, remoteIP)
				sendHTTPErrorAndClose(conn, http.StatusForbidden, "Forbidden", "账号已到期，请联系管理员充值")
				return
			}

			connInfo.mu.Lock()
			connInfo.deviceID = deviceInfo.FriendlyName
			connInfo.credential = credential
			connInfo.mu.Unlock()
		}

		ua := req.UserAgent()
		if p.cfg.Settings.UAKeywordProbe != "" && strings.Contains(ua, p.cfg.Settings.UAKeywordProbe) {
			p.Print("[*] Received probe from %s. Responding OK.", remoteIP)
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nOK"))
			continue
		}
		if p.cfg.Settings.UAKeywordWS != "" && strings.Contains(ua, p.cfg.Settings.UAKeywordWS) {
			p.Print("[*] WebSocket handshake successful for %s (Device: %s)", remoteIP, connInfo.deviceID)
			conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			handshakeComplete = true
			break
		}

		p.Print("[!] Handshake Failed: Unrecognized User-Agent '%s' from %s", ua, remoteIP)
		sendHTTPErrorAndClose(conn, http.StatusForbidden, "Forbidden", "Forbidden User-Agent")
		return
	}

	conn.SetReadDeadline(time.Time{})
	p.forwardToTarget(conn, reader, connInfo, headersText, initialData)
}

func (p *Proxy) handleDirectConnection(conn net.Conn, reader *bufio.Reader) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	connKey := fmt.Sprintf("%s-%d", remoteIP, time.Now().UnixNano())
	_, cancel := context.WithCancel(p.ctx)
	defer cancel()

	connInfo := &ActiveConnInfo{
		conn:            conn,
		connKey:         connKey,
		ip:              remoteIP,
		protocol:        "Direct TCP",
		status:          "直连",
		firstConnection: time.Now(),
		lastActive:      time.Now().Unix(),
		cancel:          cancel,
		deviceID:        "Direct TCP Connection",
	}
	p.AddActiveConn(connKey, connInfo)
	defer p.RemoveActiveConn(connKey)

	p.forwardToTarget(conn, reader, connInfo, "", nil)
}

func (p *Proxy) forwardToTarget(clientConn net.Conn, clientReader io.Reader, connInfo *ActiveConnInfo, headersText string, initialData []byte) {
	settings := p.cfg.Settings
	targetHost := settings.DefaultTargetHost
	targetPort := settings.DefaultTargetPort
	if headersText != "" {
		if realHost := extractHeaderValue(headersText, "x-real-host"); realHost != "" {
			if host, portStr, err := net.SplitHostPort(realHost); err == nil {
				targetHost = host
				if port, err := strconv.Atoi(portStr); err == nil {
					targetPort = port
				}
			} else {
				targetHost = realHost
			}
		}
	}

	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	p.Print("[*] Tunneling [%s] %s -> %s for device %s", connInfo.protocol, connInfo.ip, targetAddr, connInfo.deviceID)

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		p.Print("[!] Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	connInfo.mu.Lock()
	connInfo.status = "活跃"
	connInfo.mu.Unlock()

	if len(initialData) > 0 {
		if _, err := targetConn.Write(initialData); err != nil {
			p.Print("[!] Failed to write initial data to target for %s: %v", connInfo.ip, err)
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go p.pipeTraffic(&wg, targetConn, clientReader, connInfo, true)
	go p.pipeTraffic(&wg, clientConn, targetConn, connInfo, false)
	wg.Wait()
}

func (p *Proxy) pipeTraffic(wg *sync.WaitGroup, dst net.Conn, src io.Reader, connInfo *ActiveConnInfo, isUpload bool) {
	defer wg.Done()

	buf := getBuf(p.cfg.Settings.BufferSize)
	defer putBuf(buf)

	tracker := &copyTracker{
		Writer:   dst,
		proxy:    p,
		connInfo: connInfo,
		isUpload: isUpload,
	}

	_, err := io.CopyBuffer(tracker, src, buf)
	if err != nil {
		select {
		case <-p.ctx.Done():
		default:
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			}
		}
	}
	if tcpDst, ok := dst.(*net.TCPConn); ok {
		tcpDst.CloseWrite()
	}
}

type copyTracker struct {
	io.Writer
	proxy    *Proxy
	connInfo *ActiveConnInfo
	isUpload bool
}

func (c *copyTracker) Write(p []byte) (n int, err error) {
	n, err = c.Writer.Write(p)
	if n > 0 {
		if c.isUpload {
			atomic.AddInt64(&c.proxy.globalBytesSent, int64(n))
			atomic.AddInt64(&c.connInfo.bytesSent, int64(n))
		} else {
			atomic.AddInt64(&c.proxy.globalBytesReceived, int64(n))
			atomic.AddInt64(&c.connInfo.bytesReceived, int64(n))
		}
		if c.connInfo.credential != "" {
			if val, ok := c.proxy.deviceUsage.Load(c.connInfo.credential); ok {
				atomic.AddInt64(val.(*int64), int64(n))
			}
		}
		atomic.StoreInt64(&c.connInfo.lastActive, time.Now().Unix())
	}
	return
}
// ==========================================================
// --- 4. 辅助、API 和 Main 函数 ---
// ==========================================================

func (p *Proxy) initMetrics() {
	p.cfg.lock.RLock()
	defer p.cfg.lock.RUnlock()
	for id, info := range p.cfg.DeviceIDs {
		newUsage := info.UsedBytes
		p.deviceUsage.Store(id, &newUsage)
	}
}
func (p *Proxy) runPeriodicTasks() {
	saveTicker := time.NewTicker(5 * time.Minute)
	auditTicker := time.NewTicker(30 * time.Second)
	statusTicker := time.NewTicker(2 * time.Second)
	defer saveTicker.Stop(); defer auditTicker.Stop(); defer statusTicker.Stop()

	for {
		select {
		case <-saveTicker.C: p.saveDeviceUsage()
		case <-auditTicker.C: p.auditActiveConnections()
		case <-statusTicker.C: p.collectSystemStatus()
		case <-p.ctx.Done(): return
		}
	}
}
func (p *Proxy) saveDeviceUsage() {
	p.cfg.lock.Lock()
	defer p.cfg.lock.Unlock()
	isDirty := false
	p.deviceUsage.Range(func(key, value interface{}) bool {
		id := key.(string)
		currentUsage := atomic.LoadInt64(value.(*int64))
		if info, ok := p.cfg.DeviceIDs[id]; ok {
			if info.UsedBytes != currentUsage {
				info.UsedBytes = currentUsage
				p.cfg.DeviceIDs[id] = info
				isDirty = true
			}
		}
		return true
	})
	if isDirty {
		if err := p.cfg.SaveAtomic(); err != nil { p.Print("[!] Failed to save device usage: %v", err) }
	}
}
func (p *Proxy) auditActiveConnections() {
	idleTimeout := time.Duration(p.cfg.Settings.IdleTimeout) * time.Second
	p.conns.Range(func(key, value interface{}) bool {
		connInfo := value.(*ActiveConnInfo)
		lastActiveTime := time.Unix(atomic.LoadInt64(&connInfo.lastActive), 0)
		if time.Since(lastActiveTime) > idleTimeout {
			p.Print("[-] Auditing: Kicking idle connection for %s (device: %s)", connInfo.ip, connInfo.deviceID)
			connInfo.conn.Close()
		}
		return true
	})
}
func (p *Proxy) collectSystemStatus() {
	p.statusMutex.Lock()
	defer p.statusMutex.Unlock()
	var connCount int
	p.conns.Range(func(k, v interface{}) bool { connCount++; return true })
	cpuP, _ := cpu.Percent(0, false)
	memP, _ := mem.VirtualMemory()
	p.systemStatus = SystemStatus{
		Uptime:        time.Since(p.startTime).Round(time.Second).String(),
		CPUPercent:    cpuP[0],
		MemPercent:    memP.UsedPercent,
		NumGoroutine:  runtime.NumGoroutine(),
		ActiveConns:   connCount,
		BytesSent:     formatBytes(atomic.LoadInt64(&p.globalBytesSent)),
		BytesReceived: formatBytes(atomic.LoadInt64(&p.globalBytesReceived)),
	}
}
func (p *Proxy) AddActiveConn(key string, conn *ActiveConnInfo) { p.conns.Store(key, conn) }
func (p *Proxy) RemoveActiveConn(key string)                 { p.conns.Delete(key) }

type APIConnectionResponse struct {
	DeviceID string `json:"device_id"`; Status string `json:"status"`; Protocol string `json:"protocol"`
	SentStr string `json:"sent_str"`; RcvdStr string `json:"rcvd_str"`; SpeedStr string `json:"speed_str"`
	IP string `json:"ip"`; FirstConn string `json:"first_conn"`; LastActive string `json:"last_active"`
	ConnKey string `json:"conn_key"`
}
func (p *Proxy) handleAPIConnections(w http.ResponseWriter, r *http.Request) {
	var conns []*ActiveConnInfo
	p.conns.Range(func(key, value interface{}) bool { conns = append(conns, value.(*ActiveConnInfo)); return true })
	sort.Slice(conns, func(i, j int) bool { return conns[i].firstConnection.Before(conns[j].firstConnection) })
	resp := []APIConnectionResponse{}
	now := time.Now()
	for _, c := range conns {
		c.mu.RLock()
		status, protocol, deviceID, ip := c.status, c.protocol, c.deviceID, c.ip
		firstConn, connKey := c.firstConnection, c.connKey
		c.mu.RUnlock()
		bytesSent, bytesReceived := atomic.LoadInt64(&c.bytesSent), atomic.LoadInt64(&c.bytesReceived)
		if status == "活跃" {
			if timeDelta := now.Sub(c.lastSpeedUpdateTime).Seconds(); timeDelta >= 2 {
				currentTotalBytes := bytesSent + bytesReceived
				bytesDelta := currentTotalBytes - c.lastTotalBytesForSpeed
				if timeDelta > 0 { c.currentSpeedBps = float64(bytesDelta) / timeDelta }
				c.lastSpeedUpdateTime = now; c.lastTotalBytesForSpeed = currentTotalBytes
			}
		}
		resp = append(resp, APIConnectionResponse{
			DeviceID: deviceID, Status: status, Protocol: protocol, SentStr: formatBytes(bytesSent),
			RcvdStr: formatBytes(bytesReceived), SpeedStr: fmt.Sprintf("%s/s", formatBytes(int64(c.currentSpeedBps))),
			IP: ip, FirstConn: firstConn.Format("15:04:05"),
			LastActive: time.Unix(atomic.LoadInt64(&c.lastActive), 0).Format("15:04:05"), ConnKey: connKey,
		})
	}
	sendJSON(w, http.StatusOK, resp)
}
func (p *Proxy) handleAPIServerStatus(w http.ResponseWriter, r *http.Request) {
	p.statusMutex.RLock(); defer p.statusMutex.RUnlock(); sendJSON(w, http.StatusOK, p.systemStatus)
}
func (p *Proxy) handleAPILogs(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, http.StatusOK, p.logBuffer.GetLogs())
}
func (p *Proxy) handleAPI(w http.ResponseWriter, r *http.Request) {}
func (p *Proxy) handleAdminPost(w http.ResponseWriter, r *http.Request) {}

var adminPanelHTML, loginPanelHTML []byte
var sessions = make(map[string]Session)
var sessionsLock sync.RWMutex
type Session struct { Username string; Expiry time.Time }
const sessionCookieName = "wstunnel_session"

func (p *Proxy) authMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil { w.Header().Set("Content-Type", "text/html; charset=utf-8"); w.Write(loginPanelHTML); return }
		sessionsLock.RLock(); session, ok := sessions[cookie.Value]; sessionsLock.RUnlock()
		if !ok || time.Now().After(session.Expiry) {
			if ok { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }
			w.Header().Set("Content-Type", "text/html; charset=utf-8"); w.Write(loginPanelHTML); return
		}
		ctx := context.WithValue(r.Context(), "user", session.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
func (p *Proxy) loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct{ Username string `json:"username"`; Password string `json:"password"`}
	if json.NewDecoder(r.Body).Decode(&creds) != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效的请求格式"}); return
	}
	p.cfg.lock.RLock(); storedPass, ok := p.cfg.Accounts[creds.Username]; p.cfg.lock.RUnlock()
	if !ok { sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"}); return }
	var valid bool
	if len(storedPass) >= 60 && strings.HasPrefix(storedPass, "$2a$") {
		valid = checkPasswordHash(creds.Password, storedPass)
	} else { valid = (creds.Password == storedPass) }
	if !valid { sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"}); return }
	sessionTokenBytes := make([]byte, 32); rand.Read(sessionTokenBytes)
	sessionToken := hex.EncodeToString(sessionTokenBytes)
	expiry := time.Now().Add(12 * time.Hour)
	sessionsLock.Lock(); sessions[sessionToken] = Session{Username: creds.Username, Expiry: expiry}; sessionsLock.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: sessionToken, Expires: expiry, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	sendJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (p *Proxy) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	w.WriteHeader(http.StatusOK)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	go func() { log.Println(http.ListenAndServe("localhost:6060", nil)) }()

	var err error
	adminPanelHTML, err = os.ReadFile("admin.html")
	if err != nil { log.Printf("[!] admin.html not found, admin panel will be disabled: %v", err) }
	loginPanelHTML, err = os.ReadFile("login.html")
	if err != nil { log.Printf("[!] login.html not found, admin panel will be disabled: %v", err) }

	cfg, err := LoadConfig()
	if err != nil { log.Fatalf("[!] Failed to load config: %v", err) }

	proxy, err := NewProxy(cfg)
	if err != nil { log.Fatalf("[!] Failed to create proxy: %v", err) }

	if err := proxy.Start(); err != nil { log.Fatalf("[!] Failed to start proxy: %v", err) }

	adminMux := http.NewServeMux()
	if adminPanelHTML != nil && loginPanelHTML != nil {
		rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "text/html; charset=utf-8"); w.Write(adminPanelHTML) })
		adminMux.HandleFunc("/login", proxy.loginHandler)
		adminMux.HandleFunc("/logout", proxy.logoutHandler)
		apiHandler := http.HandlerFunc(proxy.handleAPI)
		adminPostHandler := http.HandlerFunc(proxy.handleAdminPost)
		adminMux.HandleFunc("/api/connections", proxy.authMiddleware(http.HandlerFunc(proxy.handleAPIConnections)))
		adminMux.HandleFunc("/api/server_status", proxy.authMiddleware(http.HandlerFunc(proxy.handleAPIServerStatus)))
		adminMux.HandleFunc("/api/logs", proxy.authMiddleware(http.HandlerFunc(proxy.handleAPILogs)))
		adminMux.Handle("/api/", proxy.authMiddleware(apiHandler))
		adminMux.Handle("/device/", proxy.authMiddleware(adminPostHandler))
		adminMux.Handle("/account/", proxy.authMiddleware(adminPostHandler))
		adminMux.Handle("/settings/", proxy.authMiddleware(adminPostHandler))
		adminMux.Handle("/", proxy.authMiddleware(rootHandler))
	}

	adminServer := &http.Server{Addr: cfg.Settings.AdminListenAddr, Handler: adminMux}
	go func() {
		proxy.Print("[*] Admin panel listening on %s", cfg.Settings.AdminListenAddr)
		if err := adminServer.ListenAndServe(); err != http.ErrServerClosed {
			proxy.Print("[!] Admin server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := adminServer.Shutdown(ctx); err != nil {
		proxy.Print("[!] Admin server shutdown error: %v", err)
	}
	proxy.Shutdown()
}

func sendHTTPErrorAndClose(conn net.Conn, statusCode int, statusText, body string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", statusCode, statusText, len(body), body)
	_, _ = conn.Write([]byte(response))
	conn.Close()
}
func extractHeaderValue(text, name string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?mi)^%s:\s*(.+)$`, regexp.QuoteMeta(name)))
	m := re.FindStringSubmatch(text)
	if len(m) > 1 { return strings.TrimSpace(m[1]) }
	return ""
}
func sendJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code); _, _ = w.Write(response)
}
func formatBytes(b int64) string {
	const unit = 1024; if b < unit { return fmt.Sprintf("%d B", b) }
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit { div *= unit; exp++ }
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
func isIPInList(ip string, list []string) bool {
	for _, item := range list { if item == ip { return true } }
	return false
}
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
