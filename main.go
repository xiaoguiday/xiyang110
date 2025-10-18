package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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

// 全局 Buffer Pool
var bufferPool sync.Pool

// initBufferPool 初始化 sync.Pool，用于复用[]byte切片，减少GC压力。
func initBufferPool(size int) {
	if size <= 0 {
		size = 32 * 1024 // 默认 32KB
	}
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, size)
		},
	}
}

// getBuf 从池中获取一个指定大小的缓冲区。
func getBuf(size int) []byte {
	b := bufferPool.Get().([]byte)
	if cap(b) < size {
		return make([]byte, size)
	}
	return b[:size]
}

// putBuf 将缓冲区归还到池中。
func putBuf(b []byte) {
	bufferPool.Put(b)
}

const logBufferSize = 200

// RingBuffer 用于在内存中保存最新的日志记录。
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

var logBuffer *RingBuffer

func init() { logBuffer = NewRingBuffer(logBufferSize) }
func Print(format string, v ...interface{}) { logBuffer.Add(fmt.Sprintf(format, v...)) }

var ConfigFile = "ws_config.json"

type Settings struct {
	HTTPPort                     int      `json:"http_port"`
	TLSPort                      int      `json:"tls_port"`
	StatusPort                   int      `json:"status_port"`
	DefaultTargetHost            string   `json:"default_target_host"`
	DefaultTargetPort            int      `json:"default_target_port"`
	BufferSize                   int      `json:"buffer_size"`
	Timeout                      int      `json:"timeout"`
	IdleTimeout                  int      `json:"idle_timeout"`
	CertFile                     string   `json:"cert_file"`
	KeyFile                      string   `json:"key_file"`
	UAKeywordWS                  string   `json:"ua_keyword_ws"`
	UAKeywordProbe               string   `json:"ua_keyword_probe"`
	AllowSimultaneousConnections bool     `json:"allow_simultaneous_connections"`
	DefaultExpiryDays            int      `json:"default_expiry_days"`
	DefaultLimitGB               int      `json:"default_limit_gb"`
	IPWhitelist                  []string `json:"ip_whitelist"`
	IPBlacklist                  []string `json:"ip_blacklist"`
	EnableIPWhitelist            bool     `json:"enable_ip_whitelist"`
	EnableIPBlacklist            bool     `json:"enable_ip_blacklist"`
	EnableDeviceIDAuth           bool     `json:"enable_device_id_auth"`
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
	lock      sync.RWMutex
}

var globalConfig *Config
var once sync.Once

func GetConfig() *Config {
	once.Do(func() {
		globalConfig = &Config{}
		if err := globalConfig.load(); err != nil {
			Print("[!] FATAL: Could not load or create config file: %v", err)
			os.Exit(1)
		}
	})
	return globalConfig
}
func (c *Config) load() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.Settings = Settings{
		HTTPPort:                     80,
		TLSPort:                      443,
		StatusPort:                   9090,
		DefaultTargetHost:            "127.0.0.1",
		DefaultTargetPort:            22,
		BufferSize:                   32768,
		Timeout:                      300,
		IdleTimeout:                  300,
		CertFile:                     "/etc/stunnel/certs/stunnel.pem",
		KeyFile:                      "/etc/stunnel/certs/stunnel.key",
		UAKeywordWS:                  "26.4.0",
		UAKeywordProbe:               "1.0",
		AllowSimultaneousConnections: false,
		DefaultExpiryDays:            30,
		DefaultLimitGB:               100,
		EnableDeviceIDAuth:           true,
	}
	c.Accounts = map[string]string{"admin": "admin"}
	c.DeviceIDs = make(map[string]DeviceInfo)
	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			Print("[*] %s not found, creating with default structure.", ConfigFile)
			return c.save()
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}
	if err := json.Unmarshal(data, c); err != nil {
		return fmt.Errorf("could not decode config file: %w", err)
	}
	return nil
}
func (c *Config) save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	tmpFile := ConfigFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write to temporary config file: %w", err)
	}
	if err := os.Rename(tmpFile, ConfigFile); err != nil {
		return fmt.Errorf("failed to apply config changes: %w", err)
	}
	return nil
}
func (c *Config) SafeSave() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.save()
}
func (c *Config) GetSettings() Settings {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.Settings
}
func (c *Config) GetAccounts() map[string]string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	accts := make(map[string]string)
	for k, v := range c.Accounts {
		accts[k] = v
	}
	return accts
}
func (c *Config) GetDeviceIDs() map[string]DeviceInfo {
	c.lock.RLock()
	defer c.lock.RUnlock()
	devices := make(map[string]DeviceInfo)
	for k, v := range c.DeviceIDs {
		if v.MaxSessions < 1 {
			v.MaxSessions = 1
		}
		devices[k] = v
	}
	return devices
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

type ActiveConnInfo struct {
	mu                     sync.RWMutex
	Writer                 net.Conn
	LastActive             int64
	DeviceID               string
	Credential             string
	FirstConnection        time.Time
	Status                 string
	IP                     string
	BytesSent              int64
	BytesReceived          int64
	ConnKey                string
	LastSpeedUpdateTime    time.Time
	LastTotalBytesForSpeed int64
	CurrentSpeedBps        float64
	cancel                 context.CancelFunc
}

func (c *ActiveConnInfo) Snapshot() APIConnectionResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return APIConnectionResponse{
		DeviceID:  c.DeviceID,
		Status:    c.Status,
		IP:        c.IP,
		FirstConn: c.FirstConnection.Format("15:04:05"),
		ConnKey:   c.ConnKey,
	}
}

type SystemStatus struct {
	Uptime        string  `json:"uptime"`
	CPUPercent    float64 `json:"cpu_percent"`
	CPUCores      int     `json:"cpu_cores"`
	MemTotal      uint64  `json:"mem_total"`
	MemUsed       uint64  `json:"mem_used"`
	MemPercent    float64 `json:"mem_percent"`
	BytesSent     int64   `json:"bytes_sent"`
	BytesReceived int64   `json:"bytes_received"`
}

var (
	globalBytesSent     int64
	globalBytesReceived int64
	activeConns         sync.Map
	deviceUsage         sync.Map
	startTime           = time.Now()
	systemStatus        SystemStatus
	systemStatusMutex   sync.RWMutex
	adminPanelHTML      []byte
	loginPanelHTML      []byte
)

func InitMetrics() {
	cfg := GetConfig()
	devices := cfg.GetDeviceIDs()
	for id, info := range devices {
		newUsage := info.UsedBytes
		deviceUsage.Store(id, &newUsage)
	}
}

func AddActiveConn(key string, conn *ActiveConnInfo) { activeConns.Store(key, conn) }
func RemoveActiveConn(key string)                 { activeConns.Delete(key) }
func GetActiveConn(key string) (*ActiveConnInfo, bool) {
	if val, ok := activeConns.Load(key); ok {
		return val.(*ActiveConnInfo), true
	}
	return nil, false
}

func auditActiveConnections() {
	cfg := GetConfig()
	settings := cfg.GetSettings()
	devices := cfg.GetDeviceIDs()

	activeConns.Range(func(key, value interface{}) bool {
		connInfo := value.(*ActiveConnInfo)
		var reason string
		shouldKick := false

		idleTimeout := time.Duration(settings.IdleTimeout+30) * time.Second
		lastActiveTime := time.Unix(atomic.LoadInt64(&connInfo.LastActive), 0)

		if time.Since(lastActiveTime) > idleTimeout {
			reason = fmt.Sprintf("空闲超时 (超过 %v)", idleTimeout)
			shouldKick = true
		} else if settings.EnableIPBlacklist && isIPInList(connInfo.IP, settings.IPBlacklist) {
			reason = "IP在黑名单中"
			shouldKick = true
		} else if settings.EnableDeviceIDAuth {
			if connInfo.Credential != "" {
				if devInfo, ok := devices[connInfo.Credential]; ok {
					if !devInfo.Enabled {
						reason = "设备被禁用"
						shouldKick = true
					}
					expiry, err := time.Parse("2006-01-02", devInfo.Expiry)
					if err == nil && time.Now().After(expiry.Add(24*time.Hour)) {
						reason = "设备已过期"
						shouldKick = true
					}
					if devInfo.LimitGB > 0 {
						if usageVal, usageOk := deviceUsage.Load(connInfo.Credential); usageOk {
							currentUsage := atomic.LoadInt64(usageVal.(*int64))
							if currentUsage >= int64(devInfo.LimitGB)*1024*1024*1024 {
								reason = "流量超限"
								shouldKick = true
							}
						}
					}
				} else {
					reason = "设备已被删除"
					shouldKick = true
				}
			} else if connInfo.Status == "活跃" {
				reason = "无凭证的活跃连接"
				shouldKick = true
			}
		}

		if shouldKick {
			Print("[-] [审计] 踢出连接 (原因: %s, 设备: %s, IP: %s)", reason, connInfo.DeviceID, connInfo.IP)
			if connInfo.cancel != nil {
				connInfo.cancel()
			} else {
				connInfo.Writer.Close()
			}
		}
		return true
	})
}

func runPeriodicTasks() {
	saveTicker := time.NewTicker(5 * time.Second)
	go func() {
		for range saveTicker.C {
			saveDeviceUsage()
		}
	}()
	statusTicker := time.NewTicker(2 * time.Second)
	go func() {
		for range statusTicker.C {
			collectSystemStatus()
		}
	}()
	auditTicker := time.NewTicker(15 * time.Second)
	go func() {
		for range auditTicker.C {
			auditActiveConnections()
		}
	}()
}

func saveDeviceUsage() {
	cfg := GetConfig()
	cfg.lock.Lock()
	defer cfg.lock.Unlock()
	isDirty := false
	deviceUsage.Range(func(key, value interface{}) bool {
		id := key.(string)
		currentUsage := atomic.LoadInt64(value.(*int64))
		if info, ok := cfg.DeviceIDs[id]; ok {
			if info.UsedBytes != currentUsage {
				info.UsedBytes = currentUsage
				cfg.DeviceIDs[id] = info
				isDirty = true
			}
		} else {
			deviceUsage.Delete(id)
		}
		return true
	})
	if isDirty {
		if err := cfg.save(); err != nil {
			Print("[!] Failed to save device usage: %v", err)
		}
	}
}

func collectSystemStatus() {
	systemStatusMutex.Lock()
	defer systemStatusMutex.Unlock()
	systemStatus.Uptime = time.Since(startTime).Round(time.Second).String()
	cp, err := cpu.Percent(0, false)
	if err == nil && len(cp) > 0 {
		systemStatus.CPUPercent, _ = strconv.ParseFloat(fmt.Sprintf("%.1f", cp[0]), 64)
	}
	if cores, err := cpu.Counts(true); err == nil {
		systemStatus.CPUCores = cores
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		systemStatus.MemTotal = vm.Total
		systemStatus.MemUsed = vm.Used
		systemStatus.MemPercent, _ = strconv.ParseFloat(fmt.Sprintf("%.1f", vm.UsedPercent), 64)
	}
	systemStatus.BytesSent = atomic.LoadInt64(&globalBytesSent)
	systemStatus.BytesReceived = atomic.LoadInt64(&globalBytesReceived)
}

func sendHTTPErrorAndClose(conn net.Conn, statusCode int, statusText string, body string) {
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
func isIPInList(ip string, list []string) bool {
	for _, item := range list {
		if item == ip {
			return true
		}
	}
	return false
}
func runCommand(command string, args ...string) (bool, string) {
	cmd := exec.Command(command, args...)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return false, fmt.Sprintf("Command '%s %s' failed: %v, Stderr: %s", command, strings.Join(args, " "), err, stderr.String())
	}
	return true, out.String()
}
// ==========================================================
// --- 核心连接处理 (已修正) ---
// ==========================================================

func handleClient(conn net.Conn, isTLS bool) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	Print("[+] Connection opened from %s", remoteIP)
	defer func() {
		Print("[-] Connection closed for %s", remoteIP)
		conn.Close()
	}()

	cfg := GetConfig()
	settings := cfg.GetSettings()
	connKey := fmt.Sprintf("%s-%d", remoteIP, time.Now().UnixNano())

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
	}

	if settings.EnableIPBlacklist && isIPInList(remoteIP, settings.IPBlacklist) {
		Print("[-] Connection from blacklisted IP %s rejected.", remoteIP)
		return
	}
	if settings.EnableIPWhitelist && !isIPInList(remoteIP, settings.IPWhitelist) {
		Print("[-] Connection from non-whitelisted IP %s rejected.", remoteIP)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	activeConnInfo := &ActiveConnInfo{
		Writer:          conn,
		IP:              remoteIP,
		ConnKey:         connKey,
		FirstConnection: time.Now(),
		LastActive:      time.Now().Unix(),
		Status:          "握手",
		cancel:          cancel,
	}
	AddActiveConn(connKey, activeConnInfo)
	defer RemoveActiveConn(connKey)

	reader := bufio.NewReader(conn)
	forwardingStarted := false
	var initialData []byte
	var headersText string
	var finalDeviceID string
	var credential string
	var deviceInfo DeviceInfo

	handshakeTimeout := time.Duration(settings.Timeout) * time.Second

	for !forwardingStarted {
		_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		req, err := http.ReadRequest(reader)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				Print("[-] Handshake timeout for %s after %v.", remoteIP, handshakeTimeout)
			} else if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				Print("[-] Handshake read error from %s: %v", remoteIP, err)
			}
			return
		}

		var headerBuilder strings.Builder
		_ = req.Header.Write(&headerBuilder)
		headersText = req.Method + " " + req.RequestURI + " " + req.Proto + "\r\n" + headerBuilder.String()

		req.Body = http.MaxBytesReader(nil, req.Body, 64*1024)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			Print("[!] Handshake read body error from %s: %v", remoteIP, err)
			sendHTTPErrorAndClose(conn, http.StatusBadRequest, "Bad Request", "Request body too large or invalid.")
			return
		}
		req.Body.Close()
		initialData = body

		// --- (中间的认证和逻辑判断部分没有变化) ---
		credential = req.Header.Get("Sec-WebSocket-Key")
		var found bool
		if credential != "" {
			cfg.lock.RLock()
			deviceInfo, found = cfg.DeviceIDs[credential]
			cfg.lock.RUnlock()
			if found {
				finalDeviceID = deviceInfo.FriendlyName
			}
		}

		if settings.EnableDeviceIDAuth {
			if !found {
				Print("[!] Auth Enabled: Invalid Sec-WebSocket-Key from %s. Rejecting.", remoteIP)
				sendHTTPErrorAndClose(conn, 401, "Unauthorized", "Unauthorized")
				return
			}
			if !deviceInfo.Enabled {
				Print("[!] Auth Enabled: Device '%s' is disabled. Rejecting.", finalDeviceID)
				sendHTTPErrorAndClose(conn, 403, "Forbidden", "账号被禁止,请联系管理员解锁")
				return
			}
			expiry, err := time.Parse("2006-01-02", deviceInfo.Expiry)
			if err != nil || time.Now().After(expiry.Add(24*time.Hour)) {
				Print("[!] Auth Enabled: Device '%s' has expired. Rejecting.", finalDeviceID)
				sendHTTPErrorAndClose(conn, 403, "Forbidden", "账号已到期，请联系管理员充值")
				return
			}
			var deviceUsagePtr *int64
			if val, ok := deviceUsage.Load(credential); ok {
				deviceUsagePtr = val.(*int64)
			} else {
				newUsage := deviceInfo.UsedBytes
				deviceUsage.Store(credential, &newUsage)
				deviceUsagePtr = &newUsage
			}
			if deviceInfo.LimitGB > 0 && atomic.LoadInt64(deviceUsagePtr) >= int64(deviceInfo.LimitGB)*1024*1024*1024 {
				Print("[!] Auth Enabled: Traffic limit reached for '%s'. Rejecting.", finalDeviceID)
				sendHTTPErrorAndClose(conn, 403, "Forbidden", "流量已耗尽，联系管理员充值")
				return
			}
		} else {
			if !found {
				finalDeviceID = remoteIP
			}
		}

		if !settings.AllowSimultaneousConnections && credential != "" && found {
			var existingSessionCount int
			activeConns.Range(func(key, value interface{}) bool {
				if c, ok := value.(*ActiveConnInfo); ok {
					if c.Credential == credential && c.Status == "活跃" {
						existingSessionCount++
					}
				}
				if deviceInfo.MaxSessions > 0 && existingSessionCount >= deviceInfo.MaxSessions {
					return false
				}
				return true
			})

			if deviceInfo.MaxSessions > 0 && existingSessionCount >= deviceInfo.MaxSessions {
				Print("[!] Auth: Device '%s' has reached its max session limit (%d). Rejecting.", finalDeviceID, deviceInfo.MaxSessions)
				sendHTTPErrorAndClose(conn, 409, "Conflict", fmt.Sprintf("该设备已达最大在线数 (%d)，请稍后再试", deviceInfo.MaxSessions))
				return
			}
		}
		// --- (认证逻辑结束) ---

		activeConnInfo.mu.Lock()
		activeConnInfo.DeviceID = finalDeviceID
		activeConnInfo.Credential = credential
		activeConnInfo.mu.Unlock()
		if _, ok := deviceUsage.Load(credential); !ok && credential != "" {
			newUsage := int64(0)
			deviceUsage.Store(credential, &newUsage)
		}

		ua := req.UserAgent()
		if settings.UAKeywordProbe != "" && strings.Contains(ua, settings.UAKeywordProbe) {
			Print("[*] Received probe from %s for device '%s'. Awaiting WS handshake.", remoteIP, finalDeviceID)
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nOK"))
			continue
		}
		if settings.UAKeywordWS != "" && strings.Contains(ua, settings.UAKeywordWS) {
			_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			activeConnInfo.mu.Lock()
			activeConnInfo.Status = "活跃"
			activeConnInfo.mu.Unlock()
			forwardingStarted = true
		} else {
			Print("[!] Unrecognized User-Agent from %s: '%s'. Rejecting.", remoteIP, ua)
			sendHTTPErrorAndClose(conn, 403, "Forbidden", "Forbidden")
			return
		}
	}

	_ = conn.SetReadDeadline(time.Time{})

	targetHost := settings.DefaultTargetHost
	targetPort := settings.DefaultTargetPort
	if realHost := extractHeaderValue(headersText, "x-real-host"); realHost != "" {
		if host, portStr, err := net.SplitHostPort(realHost); err == nil {
			targetHost = host
			if p, err := strconv.Atoi(portStr); err == nil {
				targetPort = p
			}
		} else {
			targetHost = realHost
		}
	}
	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	Print("[*] Tunneling %s -> %s for device %s", remoteIP, targetAddr, finalDeviceID)
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		Print("[!] Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	if tcpTargetConn, ok := targetConn.(*net.TCPConn); ok {
		tcpTargetConn.SetKeepAlive(true)
		tcpTargetConn.SetKeepAlivePeriod(30 * time.Second)
		tcpTargetConn.SetNoDelay(true)
	}

	if len(initialData) > 0 {
		if _, err := targetConn.Write(initialData); err != nil {
			Print("[!] Failed to write initial data to target: %v", err)
			return
		}
	}

	// =========================================================================
	// ### 问题1 修正说明 ###
	// 澄清 `bufio.Reader` 的生命周期问题：
	// `bufio.Reader` 在设计上会持有底层的 `io.Reader` (即`conn`)。当它的内部缓冲区被读完后，
	// 它会自动继续从 `conn` 读取。因此，在握手循环后将同一个 `reader` 传递给 `pipeTraffic`，
	// 功能上是正确的，不会导致数据丢失。`pipeTraffic` 会先消费完 `reader` 缓冲区中
	// 任何被预读的数据，然后再继续从原始 `conn` 读取新数据。
	// 这里保持代码不变，但通过此注释澄清了其健壮性。
	// =========================================================================

	// =========================================================================
	// ### 问题3 修正点 ###
	// 启动一个唯一的、更高层的 goroutine 来监控 context 的取消信号。
	// 当任一方向的 pipe 结束并调用 cancel() 时，这个 goroutine 会被激活，
	// 并强制关闭两个底层连接，从而迅速中断另一个仍在阻塞的 pipe。
	// 这取代了之前在每个 pipeTraffic 内部的监控 goroutine，
	// 将每个连接的监控 goroutine 从 2 个减少到了 1 个，提高了效率。
	// =========================================================================
	go func() {
		<-ctx.Done() // 等待 cancel() 被调用
		conn.Close()
		targetConn.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go pipeTraffic(ctx, &wg, targetConn, reader, connKey, cancel, true)
	go pipeTraffic(ctx, &wg, conn, targetConn, connKey, cancel, false)
	wg.Wait()
}

type copyTracker struct {
	io.Writer
	ConnInfo       *ActiveConnInfo
	IsUpload       bool
	DeviceUsagePtr *int64
}

func (c *copyTracker) Write(p []byte) (n int, err error) {
	n, err = c.Writer.Write(p)
	if n > 0 {
		if c.IsUpload {
			atomic.AddInt64(&globalBytesSent, int64(n))
			atomic.AddInt64(&c.ConnInfo.BytesSent, int64(n))
		} else {
			atomic.AddInt64(&globalBytesReceived, int64(n))
			atomic.AddInt64(&c.ConnInfo.BytesReceived, int64(n))
		}
		if c.ConnInfo.Credential != "" && c.DeviceUsagePtr != nil {
			atomic.AddInt64(c.DeviceUsagePtr, int64(n))
		}
		atomic.StoreInt64(&c.ConnInfo.LastActive, time.Now().Unix())
	}
	return
}

// ==========================================================
// --- pipeTraffic (已修正 goroutine 效率问题) ---
// ==========================================================
func pipeTraffic(ctx context.Context, wg *sync.WaitGroup, dst net.Conn, src io.Reader, connKey string, cancel context.CancelFunc, isUpload bool) {
	defer wg.Done()
	// 当任一方向的数据流结束（如EOF或错误），立即通过 cancel() 通知 handleClient
	// 中的监控goroutine来关闭两个连接，从而中断另一个方向的pipe。
	defer cancel()

	// ### 问题3 修正点 ###
	// 移除了内部的监控goroutine，因为它已经被 handleClient 中那个更高层的goroutine取代。

	connInfo, ok := GetActiveConn(connKey)
	if !ok {
		return
	}

	var deviceUsagePtr *int64
	if connInfo.Credential != "" {
		if val, ok := deviceUsage.Load(connInfo.Credential); ok {
			deviceUsagePtr = val.(*int64)
		}
	}

	tracker := &copyTracker{Writer: dst, ConnInfo: connInfo, IsUpload: isUpload, DeviceUsagePtr: deviceUsagePtr}

	cfg := GetConfig()
	buf := getBuf(cfg.GetSettings().BufferSize)
	defer putBuf(buf)

	// 直接执行 io.CopyBuffer。我们依赖 cancel() 触发对端连接关闭来中断这个阻塞。
	_, err := io.CopyBuffer(tracker, src, buf)

	// 错误处理：忽略由 context cancel 导致的“use of closed network connection”等预期错误。
	if err != nil && err != io.EOF {
		select {
		case <-ctx.Done():
			// 如果 context 已经关闭，那么这个错误是预期的，无需打印日志。
		default:
			// 如果 context 还未关闭，说明这是一个非预期的错误。
			Print("[!] Conn %s pipe error: %v", connKey, err)
		}
	}

	// 尝试半关闭，通知对端数据已发送完毕
	if tcpDst, ok := dst.(*net.TCPConn); ok {
		_ = tcpDst.CloseWrite()
	}
}
// ==========================================================
// --- SSH User Management (增强安全性) ---
// ==========================================================
var sshUserMgmtMutex sync.Mutex

func manageSshUser(username, password, action string) (bool, string) {
	sshUserMgmtMutex.Lock()
	defer sshUserMgmtMutex.Unlock()

	if os.Geteuid() != 0 {
		return false, "此操作需要 root 权限。"
	}
	if !regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`).MatchString(username) {
		return false, "无效的用户名。请使用小写字母、数字、下划线或连字符。"
	}
	sshdConfigPath := "/etc/ssh/sshd_config"
	startMarker := fmt.Sprintf("\n# WSTUNNEL_USER_BLOCK_START_%s\n", username)
	endMarker := fmt.Sprintf("\n# WSTUNNEL_USER_BLOCK_END_%s\n", username)

	atomicUpdateSshdConfig := func(update func(string) string) error {
		content, err := os.ReadFile(sshdConfigPath)
		if err != nil {
			return fmt.Errorf("读取 sshd_config 失败: %w", err)
		}
		backupPath := sshdConfigPath + ".bak." + time.Now().Format("20060102150405")
		if err := os.WriteFile(backupPath, content, 0644); err != nil {
			Print("[!] 创建 sshd_config 备份失败: %v", err)
		}
		newContent := update(string(content))
		tmpPath := sshdConfigPath + ".tmp"
		if err := os.WriteFile(tmpPath, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("写入临时 sshd_config 失败: %w", err)
		}
		return os.Rename(tmpPath, sshdConfigPath)
	}

	cleanUserBlock := func(content string) string {
		re := regexp.MustCompile(fmt.Sprintf(`(?s)%s.*?%s`, regexp.QuoteMeta(strings.TrimSpace(startMarker)), regexp.QuoteMeta(strings.TrimSpace(endMarker))))
		return re.ReplaceAllString(content, "")
	}

	restartSshd := func() (bool, string) {
		success, msg := runCommand("systemctl", "restart", "sshd")
		if !success {
			success, msg = runCommand("systemctl", "restart", "ssh")
		}
		if !success {
			return false, fmt.Sprintf("SSHD/SSH service restart failed: %s", msg)
		}
		return true, "SSHD/SSH service restarted successfully."
	}

	if action == "delete" {
		if err := atomicUpdateSshdConfig(cleanUserBlock); err != nil {
			return false, fmt.Sprintf("清理 sshd_config 失败: %v", err)
		}
		if exec.Command("id", username).Run() == nil {
			Print("[*] Attempting to kill all processes for user '%s' before deletion.", username)
			runCommand("pkill", "-u", username)
			time.Sleep(500 * time.Millisecond)

			delSuccess, msg := runCommand("userdel", "-r", username)
			if !delSuccess {
				return false, fmt.Sprintf("删除用户失败: %s", msg)
			}
		}
		sshdRestartSuccess, msg := restartSshd()
		if !sshdRestartSuccess {
			return false, msg
		}
		return true, fmt.Sprintf("用户 %s 及相关配置已成功删除。", username)
	}

	if action == "create" {
		if password == "" {
			return false, "创建用户时必须提供密码。"
		}
		err := atomicUpdateSshdConfig(func(content string) string {
			content = cleanUserBlock(content)
			newBlock := fmt.Sprintf("%sMatch User %s\n    PasswordAuthentication yes\n    AllowTcpForwarding yes\n    PermitTTY yes\n    AllowAgentForwarding no\n    X11Forwarding no\n    AllowStreamLocalForwarding no\n    ForceCommand /bin/echo 'This account is restricted to tunnel use only.'\n%s", startMarker, username, endMarker)
			return content + newBlock
		})
		if err != nil {
			return false, fmt.Sprintf("更新 sshd_config 失败: %v", err)
		}

		if exec.Command("id", username).Run() != nil {
			addSuccess, msg := runCommand("useradd", "-m", "-s", "/bin/bash", username)
			if !addSuccess {
				return false, fmt.Sprintf("创建用户失败: %s", msg)
			}
		}
		chpasswdCmd := exec.Command("chpasswd")
		chpasswdCmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
		if err := chpasswdCmd.Run(); err != nil {
			return false, fmt.Sprintf("设置密码失败: %v", err)
		}

		sshdRestartSuccess, msg := restartSshd()
		if !sshdRestartSuccess {
			return false, msg
		}
		return true, fmt.Sprintf("SSH 用户 '%s' 已成功创建/更新并应用了安全限制。", username)
	}

	return false, "未知操作。"
}

const sessionCookieName = "wstunnel_session"

type Session struct {
	Username string
	Expiry   time.Time
}

var (
	sessions     = make(map[string]Session)
	sessionsLock sync.RWMutex
)

func authMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		isAPIRequest := strings.HasPrefix(r.URL.Path, "/api/")

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			if isAPIRequest {
				sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized", "message": "Session cookie not found."})
			} else {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(loginPanelHTML)
			}
			return
		}

		sessionsLock.RLock()
		session, ok := sessions[cookie.Value]
		sessionsLock.RUnlock()

		if !ok || time.Now().After(session.Expiry) {
			if ok {
				sessionsLock.Lock()
				delete(sessions, cookie.Value)
				sessionsLock.Unlock()
			}
			if isAPIRequest {
				sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized", "message": "Invalid or expired session."})
			} else {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(loginPanelHTML)
			}
			return
		}

		ctx := context.WithValue(r.Context(), "user", session.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效的请求格式"})
		return
	}
	cfg := GetConfig()
	accounts := cfg.GetAccounts()
	storedPass, accountOk := accounts[creds.Username]
	if !accountOk {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"})
		return
	}
	valid := false
	if len(storedPass) >= 60 && strings.HasPrefix(storedPass, "$2a$") {
		valid = checkPasswordHash(creds.Password, storedPass)
	} else {
		valid = (creds.Password == storedPass)
	}
	if !valid {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"})
		return
	}
	sessionTokenBytes := make([]byte, 32)
	rand.Read(sessionTokenBytes)
	sessionToken := hex.EncodeToString(sessionTokenBytes)
	expiry := time.Now().Add(12 * time.Hour)
	sessionsLock.Lock()
	sessions[sessionToken] = Session{Username: creds.Username, Expiry: expiry}
	sessionsLock.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: sessionToken, Expires: expiry, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	sendJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		sessionsLock.Lock()
		delete(sessions, cookie.Value)
		sessionsLock.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusOK)
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

type APIConnectionResponse struct {
	DeviceID     string `json:"device_id"`
	Status       string `json:"status"`
	SentStr      string `json:"sent_str"`
	RcvdStr      string `json:"rcvd_str"`
	SpeedStr     string `json:"speed_str"`
	RemainingStr string `json:"remaining_str"`
	Expiry       string `json:"expiry"`
	IP           string `json:"ip"`
	FirstConn    string `json:"first_conn"`
	LastActive   string `json:"last_active"`
	ConnKey      string `json:"conn_key"`
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	cfg := GetConfig()
	var reqData map[string]interface{}
	if r.Body != nil && r.ContentLength > 0 {
		body, err := io.ReadAll(r.Body)
		if err == nil && len(body) > 0 {
			_ = json.Unmarshal(body, &reqData)
		}
	}
	switch r.URL.Path {
	case "/api/connections":
		var conns []*ActiveConnInfo
		activeConns.Range(func(key, value interface{}) bool {
			conns = append(conns, value.(*ActiveConnInfo))
			return true
		})
		sort.Slice(conns, func(i, j int) bool {
			statusOrder := map[string]int{"活跃": 0, "握手": 1}
			if statusOrder[conns[i].Status] != statusOrder[conns[j].Status] {
				return statusOrder[conns[i].Status] < statusOrder[conns[j].Status]
			}
			return conns[i].FirstConnection.Before(conns[j].FirstConnection)
		})
		devices := cfg.GetDeviceIDs()
		resp := []APIConnectionResponse{}
		now := time.Now()
		for _, c := range conns {
			snapshot := c.Snapshot()
			bytesSent := atomic.LoadInt64(&c.BytesSent)
			bytesReceived := atomic.LoadInt64(&c.BytesReceived)
			if snapshot.Status == "活跃" {
				timeDelta := now.Sub(c.LastSpeedUpdateTime).Seconds()
				if timeDelta >= 2 {
					currentTotalBytes := bytesSent + bytesReceived
					bytesDelta := currentTotalBytes - c.LastTotalBytesForSpeed
					if timeDelta > 0 {
						c.CurrentSpeedBps = float64(bytesDelta) / timeDelta
					}
					c.LastSpeedUpdateTime = now
					c.LastTotalBytesForSpeed = currentTotalBytes
				}
			}
			var deviceInfo DeviceInfo
			var found bool
			if c.Credential != "" {
				deviceInfo, found = devices[c.Credential]
			}
			remainingStr := "无限制"
			if found && deviceInfo.LimitGB > 0 {
				var currentUsage int64
				if val, ok := deviceUsage.Load(c.Credential); ok {
					currentUsage = atomic.LoadInt64(val.(*int64))
				}
				remainingBytes := int64(deviceInfo.LimitGB)*1024*1024*1024 - currentUsage
				if remainingBytes < 0 {
					remainingBytes = 0
				}
				remainingStr = formatBytes(remainingBytes)
			}
			lastActiveTimestamp := atomic.LoadInt64(&c.LastActive)
			lastActiveTime := time.Unix(lastActiveTimestamp, 0)
			resp = append(resp, APIConnectionResponse{
				DeviceID:     snapshot.DeviceID,
				Status:       snapshot.Status,
				SentStr:      formatBytes(bytesSent),
				RcvdStr:      formatBytes(bytesReceived),
				SpeedStr:     fmt.Sprintf("%s/s", formatBytes(int64(c.CurrentSpeedBps))),
				RemainingStr: remainingStr,
				Expiry:       deviceInfo.Expiry,
				IP:           snapshot.IP,
				FirstConn:    snapshot.FirstConn,
				LastActive:   lastActiveTime.Format("15:04:05"),
				ConnKey:      snapshot.ConnKey,
			})
		}
		sendJSON(w, http.StatusOK, resp)
	case "/api/kick":
		connKey, _ := reqData["conn_key"].(string)
		if conn, ok := GetActiveConn(connKey); ok {
			if conn.cancel != nil {
				conn.cancel()
			}
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "连接已踢掉"})
		} else {
			sendJSON(w, http.StatusOK, map[string]string{"status": "error", "message": "连接未找到"})
		}
	case "/api/device_usage":
		usageMap := make(map[string]int64)
		deviceUsage.Range(func(key, value interface{}) bool {
			usageMap[key.(string)] = atomic.LoadInt64(value.(*int64))
			return true
		})
		sendJSON(w, http.StatusOK, usageMap)
	case "/api/logs":
		sendJSON(w, http.StatusOK, logBuffer.GetLogs())
	case "/api/server_status":
		systemStatusMutex.RLock()
		defer systemStatusMutex.RUnlock()
		sendJSON(w, http.StatusOK, systemStatus)
	case "/api/devices":
		sendJSON(w, http.StatusOK, cfg.GetDeviceIDs())
	case "/api/settings":
		sendJSON(w, http.StatusOK, cfg.GetSettings())
	case "/api/settings/toggle_device_auth":
		enable, _ := reqData["enable"].(bool)
		cfg.lock.Lock()
		cfg.Settings.EnableDeviceIDAuth = enable
		cfg.lock.Unlock()
		if err := cfg.SafeSave(); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": err.Error()})
		} else {
			statusText := "开启"
			if !enable {
				statusText = "关闭"
			}
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": fmt.Sprintf("Device ID 验证已%s", statusText)})
		}

	case "/api/server/restart":
		sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "服务正在重启..."})
		go func() {
			time.Sleep(1 * time.Second)
			Print("[*] Manual restart triggered from admin panel.")
			executable, _ := os.Executable()
			cmd := exec.Command(executable, os.Args[1:]...)
			cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
			if err := cmd.Start(); err != nil {
				Print("[!] FATAL: Failed to restart process after manual trigger: %v", err)
				os.Exit(1)
			}
			os.Exit(0)
		}()

	case "/api/ssh/create", "/api/ssh/delete":
		action := filepath.Base(r.URL.Path)
		username, _ := reqData["username"].(string)
		password, _ := reqData["password"].(string)
		success, message := manageSshUser(username, password, action)
		status := "ok"
		if !success {
			status = "error"
		}
		sendJSON(w, http.StatusOK, map[string]string{"status": status, "message": message})
	default:
		http.NotFound(w, r)
	}
}

func handleAdminPost(w http.ResponseWriter, r *http.Request) {
	cfg := GetConfig()
	var reqData map[string]interface{}
	if json.NewDecoder(r.Body).Decode(&reqData) != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"status": "error", "message": "无效的JSON格式"})
		return
	}
	switch r.URL.Path {
	case "/device/add":
		friendlyName, _ := reqData["friendly_name"].(string)
		secWSKey, _ := reqData["sec_ws_key"].(string)
		exp, _ := reqData["expiry"].(string)
		limitStr, _ := reqData["limit_gb"].(string)
		maxSessionsRaw, _ := reqData["max_sessions"]
		if friendlyName == "" || exp == "" || secWSKey == "" {
			sendJSON(w, http.StatusBadRequest, map[string]string{"status": "error", "message": "名称, 有效期, 和设备密钥不能为空"})
			return
		}
		limit, _ := strconv.Atoi(limitStr)
		var ms int
		if val, ok := maxSessionsRaw.(float64); ok {
			ms = int(val)
		} else {
			ms = 1
		}
		if ms < 1 {
			ms = 1
		}
		cfg.lock.Lock()
		cfg.DeviceIDs[secWSKey] = DeviceInfo{FriendlyName: friendlyName, Expiry: exp, LimitGB: limit, UsedBytes: 0, MaxSessions: ms, Enabled: true}
		cfg.lock.Unlock()
		newUsage := int64(0)
		deviceUsage.Store(secWSKey, &newUsage)
		if err := cfg.SafeSave(); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": err.Error()})
		} else {
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "设备信息已保存"})
		}
	case "/device/set_status":
		secWSKey, ok1 := reqData["sec_ws_key"].(string)
		enabled, ok2 := reqData["enabled"].(bool)
		if !ok1 || !ok2 {
			sendJSON(w, http.StatusBadRequest, map[string]string{"status": "error", "message": "无效的请求，需要 sec_ws_key 和 enabled 状态"})
			return
		}
		cfg.lock.Lock()
		if info, ok := cfg.DeviceIDs[secWSKey]; ok {
			info.Enabled = enabled
			cfg.DeviceIDs[secWSKey] = info
			cfg.lock.Unlock()
			if err := cfg.SafeSave(); err != nil {
				sendJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": "保存配置失败: " + err.Error()})
			} else {
				statusText := "启用"
				if !enabled {
					statusText = "禁用"
				}
				sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": fmt.Sprintf("设备 %s 已%s", info.FriendlyName, statusText)})
			}
		} else {
			cfg.lock.Unlock()
			sendJSON(w, http.StatusNotFound, map[string]string{"status": "error", "message": "设备未找到"})
		}
	case "/device/delete":
		secWSKey, _ := reqData["sec_ws_key"].(string)
		cfg.lock.Lock()
		delete(cfg.DeviceIDs, secWSKey)
		cfg.lock.Unlock()
		deviceUsage.Delete(secWSKey)
		if err := cfg.SafeSave(); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": err.Error()})
		} else {
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "删除成功"})
		}
	case "/device/reset_traffic":
		secWSKey, _ := reqData["sec_ws_key"].(string)
		if val, ok := deviceUsage.Load(secWSKey); ok {
			atomic.StoreInt64(val.(*int64), 0)
		}
		cfg.lock.Lock()
		if info, ok := cfg.DeviceIDs[secWSKey]; ok {
			info.UsedBytes = 0
			cfg.DeviceIDs[secWSKey] = info
		}
		cfg.lock.Unlock()
		if err := cfg.SafeSave(); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": err.Error()})
		} else {
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "流量已重置"})
		}
	case "/account/update":
		ou, _ := reqData["old_user"].(string)
		op, _ := reqData["old_pass"].(string)
		nu, _ := reqData["new_user"].(string)
		np, _ := reqData["new_pass"].(string)
		accounts := cfg.GetAccounts()
		storedPass, ok := accounts[ou]
		if !ok {
			sendJSON(w, http.StatusOK, map[string]string{"status": "error", "message": "原账号不存在"})
			return
		}
		valid := false
		if len(storedPass) >= 60 && strings.HasPrefix(storedPass, "$2a$") {
			valid = checkPasswordHash(op, storedPass)
		} else {
			valid = (op == storedPass)
		}
		if !valid {
			sendJSON(w, http.StatusOK, map[string]string{"status": "error", "message": "原密码错误"})
			return
		}
		h, err := hashPassword(np)
		if err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": "密码加密失败"})
			return
		}
		cfg.lock.Lock()
		if ou != nu {
			delete(cfg.Accounts, ou)
		}
		cfg.Accounts[nu] = h
		cfg.lock.Unlock()
		if err := cfg.SafeSave(); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": err.Error()})
		} else {
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "账号密码已更新，请重新登录！"})
		}
	case "/settings/save":
		oldSettings := cfg.GetSettings()
		oldPorts := []int{oldSettings.HTTPPort, oldSettings.TLSPort, oldSettings.StatusPort}
		var newSettings Settings
		settingsBytes, _ := json.Marshal(reqData)
		_ = json.Unmarshal(settingsBytes, &newSettings)
		cfg.lock.Lock()
		cfg.Settings = newSettings
		cfg.lock.Unlock()
		if err := cfg.SafeSave(); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": fmt.Sprintf("保存失败: %v", err)})
			return
		}
		newPorts := []int{newSettings.HTTPPort, newSettings.TLSPort, newSettings.StatusPort}
		portsChanged := false
		for i := range oldPorts {
			if oldPorts[i] != newPorts[i] {
				portsChanged = true
				break
			}
		}
		if portsChanged {
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "端口设置已更改, 服务正在重启..."})
			go func() {
				time.Sleep(1 * time.Second)
				Print("[*] Port settings changed. Restarting server...")
				executable, _ := os.Executable()
				cmd := exec.Command(executable, os.Args[1:]...)
				cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
				if err := cmd.Start(); err != nil {
					Print("[!] FATAL: Failed to restart process: %v", err)
					os.Exit(1)
				}
				os.Exit(0)
			}()
		} else {
			Print("[*] Settings updated and hot-reloaded successfully.")
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "设置已保存并热加载成功！"})
		}
	}
}
func main() {
	go func() {
		log.Println("Starting pprof server on http://localhost:6060/debug/pprof")
		if err := http.ListenAndServe("localhost:6060", nil); err != nil {
			Print("[!] PPROF: Failed to start pprof server: %v", err)
		}
	}()
	log.SetOutput(io.Discard)

	var err error
	adminPanelHTML, err = os.ReadFile("admin.html")
	if err != nil {
		Print("[!] FATAL: admin.html not found: %v", err)
		os.Exit(1)
	}
	loginPanelHTML, err = os.ReadFile("login.html")
	if err != nil {
		Print("[!] FATAL: login.html not found: %v", err)
		os.Exit(1)
	}

	Print("[*] WSTunnel-Go starting...")
	cfg := GetConfig()
	initBufferPool(cfg.Settings.BufferSize)
	InitMetrics()
	settings := cfg.GetSettings()

	runPeriodicTasks()

	// 强制监听IPv4以解决某些环境下双栈监听不生效的问题
	httpAddr := fmt.Sprintf("0.0.0.0:%d", settings.HTTPPort)
	httpListener, err := net.Listen("tcp4", httpAddr)
	if err != nil {
		Print("[!] FATAL: Failed to listen on HTTP port %d (IPv4): %v", settings.HTTPPort, err)
		os.Exit(1)
	}
	Print("[*] WS on %s (IPv4)", httpAddr)
	go func() {
		for {
			conn, err := httpListener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					break
				}
				Print("[!] WS accept error: %v", err)
				continue
			}
			go handleClient(conn, false)
		}
	}()

	var tlsListener net.Listener
	if _, err := os.Stat(settings.CertFile); err == nil {
		if _, err := os.Stat(settings.KeyFile); err == nil {
			cert, err := tls.LoadX509KeyPair(settings.CertFile, settings.KeyFile)
			if err != nil {
				Print("[!] Cert warning: %v. WSS server will not start.", err)
			} else {
				tlsAddr := fmt.Sprintf("0.0.0.0:%d", settings.TLSPort)
				tlsListener, err = tls.Listen("tcp4", tlsAddr, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err != nil {
					Print("[!] FATAL: Failed to listen on %s (TLS, IPv4): %v", tlsAddr, err)
				} else {
					Print("[*] WSS on %s (IPv4)", tlsAddr)
					go func() {
						for {
							conn, err := tlsListener.Accept()
							if err != nil {
								if strings.Contains(err.Error(), "use of closed network connection") {
									break
								}
								Print("[!] WSS accept error: %v", err)
								continue
							}
							go handleClient(conn, true)
						}
					}()
				}
			}
		} else {
			Print("[!] TLS Key file '%s' not found. WSS server will not start.", settings.KeyFile)
		}
	} else {
		Print("[!] TLS Cert file '%s' not found. WSS server will not start.", settings.CertFile)
	}

	adminMux := http.NewServeMux()
	adminRootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := r.Context().Value("user").(string)
		html := string(adminPanelHTML)
		meta_tag := fmt.Sprintf(`<meta name="user-context" content="%s">`, user)
		finalHTML := strings.Replace(html, "<head>", "<head>\n    "+meta_tag, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(finalHTML))
	})
	adminMux.Handle("/", authMiddleware(adminRootHandler))
	adminMux.HandleFunc("/login", loginHandler)
	adminMux.HandleFunc("/logout", logoutHandler)

	apiHandler := http.HandlerFunc(handleAPI)
	adminPostHandler := http.HandlerFunc(handleAdminPost)
	adminMux.Handle("/api/", authMiddleware(apiHandler))
	adminMux.Handle("/device/", authMiddleware(adminPostHandler))
	adminMux.Handle("/account/", authMiddleware(adminPostHandler))
	adminMux.Handle("/settings/", authMiddleware(adminPostHandler))

	adminAddr := fmt.Sprintf("0.0.0.0:%d", settings.StatusPort)
	adminServer := &http.Server{Addr: adminAddr, Handler: adminMux}
	Print("[*] Status server listening on %s (accessible at http://127.0.0.1:%d)", adminAddr, settings.StatusPort)
	go func() {
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			Print("[!] FATAL: Failed to start admin server on %s: %v", adminAddr, err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	Print("\n[*] Shutting down server...")

	httpListener.Close()
	if tlsListener != nil {
		tlsListener.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := adminServer.Shutdown(ctx); err != nil {
		Print("[!] Admin server shutdown failed: %v", err)
	}

	Print("[*] Waiting for existing connections to finish...")
	time.Sleep(2 * time.Second)

	saveDeviceUsage()

	Print("[*] Server gracefully stopped.")
}
