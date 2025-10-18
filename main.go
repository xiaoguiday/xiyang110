package main

import (
	"bufio"
	"bytes"
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
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
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

// --- 配置文件结构 ---
type Settings struct {
	ListenAddrs       []string `json:"listen_addrs"`
	AdminListenAddr   string   `json:"admin_listen_addr"`
	DefaultTargetHost string   `json:"default_target_host"`
	DefaultTargetPort int      `json:"default_target_port"`
	BufferSize        int      `json:"buffer_size"`
	HandshakePeek     int      `json:"handshake_peek"`
	HandshakeTimeout  int      `json:"handshake_timeout"`
	IdleTimeout       int      `json:"idle_timeout"`
	MaxConns          int      `json:"max_conns"`
	EnableAuth        bool     `json:"enable_auth"`
	UAKeywordWS       string   `json:"ua_keyword_ws"`
	UAKeywordProbe    string   `json:"ua_keyword_probe"`
	CertFile          string   `json:"cert_file"`
	KeyFile           string   `json:"key_file"`
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
	DeviceIDs map[string]DeviceInfo `json:"device_ids"`
	Accounts  map[string]string     `json:"accounts"`
	lock      sync.RWMutex          `json:"-"`
}

// --- 核心 Proxy 结构体 ---
type Proxy struct {
	cfg           *Config
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	startTime     time.Time
	conns         sync.Map
	deviceUsage   sync.Map
	tlsConfig     *tls.Config
	connSemaphore chan struct{}

	globalBytesSent     int64
	globalBytesReceived int64

	logBuffer *RingBuffer
}

// --- 连接信息结构 ---
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

// --- 日志与工具函数 ---
var bufferPool sync.Pool

func initBufferPool(size int) {
	if size <= 0 {
		size = 32 * 1024
	}
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, size)
		},
	}
}
func getBuf(size int) []byte {
	b := bufferPool.Get().([]byte)
	if cap(b) < size {
		return make([]byte, size)
	}
	return b[:size]
}
func putBuf(b []byte) {
	bufferPool.Put(b)
}

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

// --- 配置加载与保存 ---
func defaultConfig() *Config {
	return &Config{
		Settings: Settings{
			ListenAddrs:       []string{"0.0.0.0:80", "0.0.0.0:443"},
			AdminListenAddr:   "127.0.0.1:9090",
			DefaultTargetHost: "127.0.0.1",
			DefaultTargetPort: 22,
			BufferSize:        32768,
			HandshakePeek:     1024,
			HandshakeTimeout:  5,
			IdleTimeout:       300,
			MaxConns:          4096,
			EnableAuth:        true,
			UAKeywordWS:       "26.4.0",
			UAKeywordProbe:    "probe",
			CertFile:          "cert.pem",
			KeyFile:           "key.pem",
		},
		DeviceIDs: make(map[string]DeviceInfo),
		Accounts:  map[string]string{"admin": "admin"},
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
	cfg := defaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
// ==========================================================
// --- 2. Proxy 核心实现 (生命周期, 监听, 协议嗅探) ---
// ==========================================================

// NewProxy 创建一个新的 Proxy 实例
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
	}

	initBufferPool(p.cfg.Settings.BufferSize)
	p.initMetrics()
	return p, nil
}

// Start 启动代理服务
func (p *Proxy) Start() error {
	if len(p.cfg.Settings.ListenAddrs) == 0 {
		return errors.New("no listen addresses configured")
	}

	var listeners []net.Listener
	for _, addr := range p.cfg.Settings.ListenAddrs {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			p.Print("[!] cannot listen on %s: %v", addr, err)
			continue
		}
		p.Print("[*] Proxy listening on %s", addr)
		listeners = append(listeners, l)

		p.wg.Add(1)
		go p.acceptLoop(l)
	}

	if len(listeners) == 0 {
		return errors.New("no valid listeners started")
	}

	go p.runPeriodicTasks()
	return nil
}

// Shutdown 优雅地关闭代理服务
func (p *Proxy) Shutdown() {
	p.Print("[*] Shutting down server...")
	p.cancel()
	p.wg.Wait()
	p.saveDeviceUsage()
	p.Print("[*] Server gracefully stopped.")
}

// acceptLoop 是每个监听器的受理循环
func (p *Proxy) acceptLoop(l net.Listener) {
	defer p.wg.Done()
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				p.Print("[!] accept error on %s: %v", l.Addr().String(), err)
				time.Sleep(100 * time.Millisecond)
				continue
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

// handleConnection - 协议多路复用的核心入口
func (p *Proxy) handleConnection(conn net.Conn) {
	defer conn.Close()
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	p.Print("[+] Connection opened from %s", remoteIP)

	timeout := time.Duration(p.cfg.Settings.HandshakeTimeout) * time.Second
	conn.SetReadDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	peekedBytes, err := reader.Peek(p.cfg.Settings.HandshakePeek)
	if err != nil {
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				p.Print("[-] Peek error from %s: %v", remoteIP, err)
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
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()

	connInfo := &ActiveConnInfo{
		conn:            conn,
		connKey:         connKey,
		ip:              remoteIP,
		protocol:        "HTTP",
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
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
					p.Print("[-] HTTP handshake read error from %s: %v", remoteIP, err)
				}
			}
			return
		}

		var headerBuilder strings.Builder
		req.Header.Write(&headerBuilder)
		headersText = req.Method + " " + req.RequestURI + " " + req.Proto + "\r\n" + headerBuilder.String()

		req.Body = http.MaxBytesReader(nil, req.Body, 64*1024)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			sendHTTPErrorAndClose(conn, http.StatusBadRequest, "Bad Request", "Request body too large or invalid.")
			return
		}
		req.Body.Close()
		initialData = body

		if p.cfg.Settings.EnableAuth {
			credential := req.Header.Get("Sec-WebSocket-Key")
			if credential == "" {
				p.Print("[!] Auth Enabled: Missing Sec-WebSocket-Key from %s. Rejecting.", remoteIP)
				sendHTTPErrorAndClose(conn, http.StatusUnauthorized, "Unauthorized", "Unauthorized")
				return
			}
			p.cfg.lock.RLock()
			deviceInfo, found := p.cfg.DeviceIDs[credential]
			p.cfg.lock.RUnlock()

			if !found {
				p.Print("[!] Auth Enabled: Invalid Sec-WebSocket-Key from %s. Rejecting.", remoteIP)
				sendHTTPErrorAndClose(conn, http.StatusUnauthorized, "Unauthorized", "Unauthorized")
				return
			}
			if !deviceInfo.Enabled {
				sendHTTPErrorAndClose(conn, http.StatusForbidden, "Forbidden", "账号被禁止,请联系管理员解锁")
				return
			}
			expiry, err := time.Parse("2006-01-02", deviceInfo.Expiry)
			if err != nil || time.Now().After(expiry.Add(24*time.Hour)) {
				sendHTTPErrorAndClose(conn, http.StatusForbidden, "Forbidden", "账号已到期，请联系管理员充值")
				return
			}
			// ... (省略流量和会话数检查) ...

			connInfo.mu.Lock()
			connInfo.deviceID = deviceInfo.FriendlyName
			connInfo.credential = credential
			connInfo.mu.Unlock()
		}

		ua := req.UserAgent()
		if p.cfg.Settings.UAKeywordProbe != "" && strings.Contains(ua, p.cfg.Settings.UAKeywordProbe) {
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nOK"))
			continue
		}
		if p.cfg.Settings.UAKeywordWS != "" && strings.Contains(ua, p.cfg.Settings.UAKeywordWS) {
			conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			handshakeComplete = true
			break
		}

		p.Print("[!] Unrecognized User-Agent from %s: '%s'. Rejecting.", remoteIP, ua)
		sendHTTPErrorAndClose(conn, http.StatusForbidden, "Forbidden", "Forbidden")
		return
	}

	conn.SetReadDeadline(time.Time{})
	p.forwardToTarget(conn, reader, connInfo, headersText, initialData)
}

func (p *Proxy) handleDirectConnection(conn net.Conn, reader *bufio.Reader) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	connKey := fmt.Sprintf("%s-%d", remoteIP, time.Now().UnixNano())
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()

	connInfo := &ActiveConnInfo{
		conn:            conn,
		connKey:         connKey,
		ip:              remoteIP,
		protocol:        "Direct",
		status:          "直连",
		firstConnection: time.Now(),
		lastActive:      time.Now().Unix(),
		cancel:          cancel,
		deviceID:        "Direct TCP",
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

	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		clientConn.Close()
		targetConn.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go p.pipeTraffic(ctx, &wg, targetConn, clientReader, connInfo, true)
	go p.pipeTraffic(ctx, &wg, clientConn, targetConn, connInfo, false)
	wg.Wait()
}

func (p *Proxy) pipeTraffic(ctx context.Context, wg *sync.WaitGroup, dst net.Conn, src io.Reader, connInfo *ActiveConnInfo, isUpload bool) {
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
		case <-ctx.Done():
		default:
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				p.Print("[!] Pipe error for conn %s: %v", connInfo.connKey, err)
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

// --- 后台任务与统计 ---
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
	defer saveTicker.Stop()
	defer auditTicker.Stop()

	for {
		select {
		case <-saveTicker.C:
			p.saveDeviceUsage()
		case <-auditTicker.C:
			p.auditActiveConnections()
		case <-p.ctx.Done():
			return
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
		if err := p.cfg.SaveAtomic(); err != nil {
			p.Print("[!] Failed to save device usage: %v", err)
		}
	}
}
func (p *Proxy) auditActiveConnections() {
	idleTimeout := time.Duration(p.cfg.Settings.IdleTimeout) * time.Second
	p.conns.Range(func(key, value interface{}) bool {
		connInfo := value.(*ActiveConnInfo)
		lastActiveTime := time.Unix(atomic.LoadInt64(&connInfo.lastActive), 0)

		if time.Since(lastActiveTime) > idleTimeout {
			p.Print("[!] Auditing: Kicking idle connection for %s (device: %s)", connInfo.ip, connInfo.deviceID)
			connInfo.conn.Close() // 这会触发 pipe 的结束
		}
		return true
	})
}
func (p *Proxy) AddActiveConn(key string, conn *ActiveConnInfo) { p.conns.Store(key, conn) }
func (p *Proxy) RemoveActiveConn(key string)                 { p.conns.Delete(key) }
func (p *Proxy) GetActiveConn(key string) (*ActiveConnInfo, bool) {
	if val, ok := p.conns.Load(key); ok {
		return val.(*ActiveConnInfo), true
	}
	return nil, false
}

// --- API Handlers ---
type APIConnectionResponse struct {
	DeviceID     string `json:"device_id"`
	Status       string `json:"status"`
	Protocol     string `json:"protocol"`
	SentStr      string `json:"sent_str"`
	RcvdStr      string `json:"rcvd_str"`
	SpeedStr     string `json:"speed_str"`
	IP           string `json:"ip"`
	FirstConn    string `json:"first_conn"`
	LastActive   string `json:"last_active"`
	ConnKey      string `json:"conn_key"`
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

func (p *Proxy) handleAPIConnections(w http.ResponseWriter, r *http.Request) {
	var conns []*ActiveConnInfo
	p.conns.Range(func(key, value interface{}) bool {
		conns = append(conns, value.(*ActiveConnInfo))
		return true
	})
	sort.Slice(conns, func(i, j int) bool {
		return conns[i].firstConnection.Before(conns[j].firstConnection)
	})

	resp := []APIConnectionResponse{}
	now := time.Now()
	for _, c := range conns {
		c.mu.RLock()
		status := c.status
		protocol := c.protocol
		deviceID := c.deviceID
		ip := c.ip
		firstConn := c.firstConnection
		connKey := c.connKey
		c.mu.RUnlock()

		bytesSent := atomic.LoadInt64(&c.bytesSent)
		bytesReceived := atomic.LoadInt64(&c.bytesReceived)
		
		if status == "活跃" {
			timeDelta := now.Sub(c.lastSpeedUpdateTime).Seconds()
			if timeDelta >= 2 {
				currentTotalBytes := bytesSent + bytesReceived
				bytesDelta := currentTotalBytes - c.lastTotalBytesForSpeed
				if timeDelta > 0 {
					c.currentSpeedBps = float64(bytesDelta) / timeDelta
				}
				c.lastSpeedUpdateTime = now
				c.lastTotalBytesForSpeed = currentTotalBytes
			}
		}

		resp = append(resp, APIConnectionResponse{
			DeviceID:     deviceID,
			Status:       status,
			Protocol:     protocol,
			SentStr:      formatBytes(bytesSent),
			RcvdStr:      formatBytes(bytesReceived),
			SpeedStr:     fmt.Sprintf("%s/s", formatBytes(int64(c.currentSpeedBps))),
			IP:           ip,
			FirstConn:    firstConn.Format("15:04:05"),
			LastActive:   time.Unix(atomic.LoadInt64(&c.lastActive), 0).Format("15:04:05"),
			ConnKey:      connKey,
		})
	}
	sendJSON(w, http.StatusOK, resp)
}
func (p *Proxy) handleAPIServerStatus(w http.ResponseWriter, r *http.Request) {
	var connCount int
	p.conns.Range(func(key, value interface{}) bool {
		connCount++
		return true
	})
	cpuPercent, _ := cpu.Percent(0, false)
	memInfo, _ := mem.VirtualMemory()

	status := SystemStatus{
		Uptime:        time.Since(p.startTime).Round(time.Second).String(),
		CPUPercent:    cpuPercent[0],
		MemPercent:    memInfo.UsedPercent,
		NumGoroutine:  runtime.NumGoroutine(),
		ActiveConns:   connCount,
		BytesSent:     formatBytes(atomic.LoadInt64(&p.globalBytesSent)),
		BytesReceived: formatBytes(atomic.LoadInt64(&p.globalBytesReceived)),
	}
	sendJSON(w, http.StatusOK, status)
}
func (p *Proxy) handleAPILogs(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, http.StatusOK, p.logBuffer.GetLogs())
}

// --- Web 面板与 Main ---
var adminPanelHTML, loginPanelHTML []byte

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var err error
	adminPanelHTML, err = os.ReadFile("admin.html")
	if err != nil {
		log.Printf("[!] admin.html not found, admin panel will be disabled: %v", err)
	}
	loginPanelHTML, err = os.ReadFile("login.html")
	if err != nil {
		log.Printf("[!] login.html not found, admin panel will be disabled: %v", err)
	}

	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("[!] Failed to load config: %v", err)
	}

	proxy, err := NewProxy(cfg)
	if err != nil {
		log.Fatalf("[!] Failed to create proxy: %v", err)
	}

	if err := proxy.Start(); err != nil {
		log.Fatalf("[!] Failed to start proxy: %v", err)
	}

	// 启动独立的管理面板服务
	adminMux := http.NewServeMux()
	if adminPanelHTML != nil && loginPanelHTML != nil {
		adminMux.HandleFunc("/api/connections", proxy.handleAPIConnections)
		adminMux.HandleFunc("/api/server_status", proxy.handleAPIServerStatus)
		adminMux.HandleFunc("/api/logs", proxy.handleAPILogs)
		// ... (注册其他所有API和管理后台的handler)
	}
	
	adminServer := &http.Server{Addr: cfg.Settings.AdminListenAddr, Handler: adminMux}
	go func() {
		proxy.Print("[*] Admin panel listening on %s", cfg.Settings.AdminListenAddr)
		if err := adminServer.ListenAndServe(); err != http.ErrServerClosed {
			proxy.Print("[!] Admin server error: %v", err)
		}
	}()

	// 优雅停机
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

// --- 剩余的辅助函数 ---
func sendHTTPErrorAndClose(conn net.Conn, statusCode int, statusText, body string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		statusCode, statusText, len(body), body)
	_, _ = conn.Write([]byte(response))
	conn.Close()
}
func extractHeaderValue(text, name string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?mi)^%s:\s*(.+)$`, regexp.QuoteMeta(name)))
	m := re.FindStringSubmatch(text)
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}
func sendJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(response)
}
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
