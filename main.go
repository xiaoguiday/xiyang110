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
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/crypto/bcrypt"
)

// I/O缓冲区池
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

const logBufferSize = 200

// 环形日志缓冲区
type RingBuffer struct {
	mu     sync.RWMutex
	buffer []string
	head   int
}

func NewRingBuffer(capacity int) *RingBuffer { return &RingBuffer{buffer: make([]string, capacity)} }
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

// --- 配置结构体与管理 (内存快照 + 定期回写模型) ---
var ConfigFile = "ws_config.json"

type Settings struct {
	HTTPPort                     int      `json:"http_port"`
	TLSPort                      int      `json:"tls_port"`
	StatusPort                   int      `json:"status_port"`
	DefaultTargetHost            string   `json:"default_target_host"`
	DefaultTargetPort            int      `json:"default_target_port"`
	BufferSize                   int      `json:"buffer_size"`
	Timeout                      int      `json:"timeout"`
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
	Settings  Settings                `json:"settings"`
	Accounts  map[string]string       `json:"accounts"`
	DeviceIDs map[string]DeviceInfo `json:"device_ids"`
	lock      sync.RWMutex
}

var globalConfig *Config
var once sync.Once

func GetConfig() *Config {
	once.Do(func() {
		globalConfig = &Config{}
		if err := globalConfig.loadFromDisk(); err != nil {
			Print("[!] FATAL: Could not load or create config file: %v", err)
			os.Exit(1)
		}
	})
	return globalConfig
}
func (c *Config) loadFromDisk() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.Settings = Settings{HTTPPort: 80, TLSPort: 443, StatusPort: 9090, DefaultTargetHost: "127.0.0.1", DefaultTargetPort: 22, BufferSize: 32768, Timeout: 300, CertFile: "/etc/stunnel/certs/stunnel.pem", KeyFile: "/etc/stunnel/certs/stunnel.key", UAKeywordWS: "26.4.0", UAKeywordProbe: "1.0", AllowSimultaneousConnections: false, DefaultExpiryDays: 30, DefaultLimitGB: 100, EnableDeviceIDAuth: true}
	c.Accounts = map[string]string{"admin": "admin"}
	c.DeviceIDs = make(map[string]DeviceInfo)
	data, err := ioutil.ReadFile(ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			Print("[*] %s not found, creating with default structure.", ConfigFile)
			return c.saveToDisk()
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}
	if err := json.Unmarshal(data, c); err != nil {
		return fmt.Errorf("could not decode config file: %w. Please check its format", err)
	}
	return nil
}
func (c *Config) saveToDisk() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil { return fmt.Errorf("failed to marshal config: %w", err) }
	return ioutil.WriteFile(ConfigFile, data, 0644)
}
func (c *Config) SafeSave() {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if err := c.saveToDisk(); err != nil {
		Print("[!] Failed to save config to disk: %v", err)
	}
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// --- 系统状态与连接信息 ---
type ActiveConnInfo struct {
	Writer                 net.Conn
	LastActive             atomic.Int64
	DeviceID               string
	Credential             string
	FirstConnection        time.Time
	Status                 string
	IP                     string
	BytesSent              atomic.Int64
	BytesReceived          atomic.Int64
	ConnKey                string
	LastSpeedUpdateTime    time.Time
	LastTotalBytesForSpeed int64
	CurrentSpeedBps        float64
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
	globalBytesSent     atomic.Int64
	globalBytesReceived atomic.Int64
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
	cfg.lock.RLock()
	defer cfg.lock.RUnlock()
	for id, info := range cfg.DeviceIDs {
		initialUsage := info.UsedBytes
		deviceUsage.Store(id, &initialUsage)
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

// --- 后台周期性任务 ---

// auditActiveConnections (生产版本 - 安静模式)
func auditActiveConnections() {
	cfg := GetConfig()
	activeConns.Range(func(key, value interface{}) bool {
		connInfo := value.(*ActiveConnInfo)
		
		cfg.lock.RLock()
		settings := cfg.Settings
		if settings.EnableIPBlacklist && isIPInList(connInfo.IP, settings.IPBlacklist) {
			cfg.lock.RUnlock()
			Print("[审计] 触发踢出: IP %s 被列入黑名单。", connInfo.IP)
			connInfo.Writer.Close()
			return true 
		}
		if !settings.EnableDeviceIDAuth {
			cfg.lock.RUnlock()
			return true
		}
		if connInfo.Credential == "" {
			cfg.lock.RUnlock()
			Print("[审计] 触发踢出: 连接无凭证，但设备认证已开启。IP: %s", connInfo.IP)
			connInfo.Writer.Close()
			return true
		}
		devInfo, ok := cfg.DeviceIDs[connInfo.Credential]
		cfg.lock.RUnlock()

		if !ok {
			Print("[审计] 触发踢出: 设备凭证 '%s' 不再存在。", connInfo.Credential)
			connInfo.Writer.Close()
			return true
		}

		if !devInfo.Enabled {
			Print("[审计] 触发踢出: 设备 '%s' 已被禁用。", connInfo.DeviceID)
			connInfo.Writer.Close()
			return true
		}

		expiry, err := time.Parse("2006-01-02", devInfo.Expiry)
		if err == nil {
			if time.Now().After(expiry.Add(24 * time.Hour)) {
				Print("[审计] 触发踢出: 设备 '%s' 已于 '%s' 过期。", connInfo.DeviceID, devInfo.Expiry)
				connInfo.Writer.Close()
				return true
			}
		}
		
		if devInfo.LimitGB > 0 {
			if usageVal, usageOk := deviceUsage.Load(connInfo.Credential); usageOk {
				currentUsage := atomic.LoadInt64(usageVal.(*int64))
				limitBytes := int64(devInfo.LimitGB) * 1024 * 1024 * 1024
				if currentUsage >= limitBytes {
					Print("[审计] 触发踢出: 设备 '%s' 流量超限。", connInfo.DeviceID)
					connInfo.Writer.Close()
					return true
				}
			}
		}

		return true
	})
}


func runPeriodicTasks() {
	cfg := GetConfig()
	// 任务1: 同步流量数据到内存Config
	trafficSyncTicker := time.NewTicker(5 * time.Second)
	go func() {
		for range trafficSyncTicker.C {
			cfg.lock.Lock()
			deviceUsage.Range(func(key, value interface{}) bool {
				id := key.(string)
				currentUsage := atomic.LoadInt64(value.(*int64))
				if info, ok := cfg.DeviceIDs[id]; ok {
					info.UsedBytes = currentUsage
					cfg.DeviceIDs[id] = info
				}
				return true
			})
			cfg.lock.Unlock()
		}
	}()
	// 任务2: 定期将内存Config写入硬盘
	diskSaveTicker := time.NewTicker(10 * time.Second)
	go func() {
		for range diskSaveTicker.C {
			cfg.SafeSave()
		}
	}()
	// 任务3: 收集服务器状态
	statusTicker := time.NewTicker(2 * time.Second)
	go func() {
		for range statusTicker.C { collectSystemStatus() }
	}()
	// 任务4: 执行连接审计
	auditTicker := time.NewTicker(15 * time.Second)
	go func() {
		for range auditTicker.C { auditActiveConnections() }
	}()
}
func collectSystemStatus() {
	systemStatusMutex.Lock()
	defer systemStatusMutex.Unlock()
	systemStatus.Uptime = time.Since(startTime).Round(time.Second).String()
	cp, err := cpu.Percent(0, false)
	if err == nil && len(cp) > 0 { systemStatus.CPUPercent, _ = strconv.ParseFloat(fmt.Sprintf("%.1f", cp[0]), 64) }
	if cores, err := cpu.Counts(true); err == nil { systemStatus.CPUCores = cores }
	if vm, err := mem.VirtualMemory(); err == nil {
		systemStatus.MemTotal = vm.Total
		systemStatus.MemUsed = vm.Used
		systemStatus.MemPercent, _ = strconv.ParseFloat(fmt.Sprintf("%.1f", vm.UsedPercent), 64)
	}
	systemStatus.BytesSent = globalBytesSent.Load()
	systemStatus.BytesReceived = globalBytesReceived.Load()
}

// Reader/Writer 包装器，实现双端心跳更新
type writeTracker struct {
	io.Writer
	connInfo   *ActiveConnInfo
	isUpload   bool
	credential string
}
func (wt *writeTracker) Write(p []byte) (n int, err error) {
	n, err = wt.Writer.Write(p)
	if n > 0 {
		if wt.isUpload {
			globalBytesSent.Add(int64(n))
			wt.connInfo.BytesSent.Add(int64(n))
		} else {
			globalBytesReceived.Add(int64(n))
			wt.connInfo.BytesReceived.Add(int64(n))
		}
		if wt.credential != "" {
			if val, ok := deviceUsage.Load(wt.credential); ok {
				atomic.AddInt64(val.(*int64), int64(n))
			}
		}
		wt.connInfo.LastActive.Store(time.Now().Unix())
	}
	return
}
type readTracker struct {
	io.Reader
	connInfo *ActiveConnInfo
}
func (rt *readTracker) Read(p []byte) (n int, err error) {
	n, err = rt.Reader.Read(p)
	if n > 0 {
		rt.connInfo.LastActive.Store(time.Now().Unix())
	}
	return
}

// pipeTraffic 使用包装器恢复 io.Copy 的高性能
func pipeTraffic(wg *sync.WaitGroup, dst io.Writer, src io.Reader, connInfo *ActiveConnInfo, credential string, isUpload bool, cancel context.CancelFunc) {
	defer wg.Done()
	defer cancel()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	writerWithTracking := &writeTracker{
		Writer:     dst,
		connInfo:   connInfo,
		isUpload:   isUpload,
		credential: credential,
	}
	readerWithTracking := &readTracker{
		Reader:   src,
		connInfo: connInfo,
	}
	
	io.CopyBuffer(writerWithTracking, readerWithTracking, buf)
	
	if tcpConn, ok := dst.(net.Conn); ok {
		if conn, ok := tcpConn.(*net.TCPConn); ok {
			_ = conn.CloseWrite()
		}
	}
}


func handleClient(conn net.Conn, isTLS bool) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	Print("[+] Connection opened from %s", remoteIP)
	defer func() {
		Print("[-] Connection closed for %s", remoteIP)
		conn.Close()
	}()

	cfg := GetConfig()
	cfg.lock.RLock()
	settings := cfg.Settings
	cfg.lock.RUnlock()

	connKey := fmt.Sprintf("%s-%d", remoteIP, time.Now().UnixNano())

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	if settings.EnableIPBlacklist && isIPInList(remoteIP, settings.IPBlacklist) {
		Print("[-] Connection from blacklisted IP %s rejected.", remoteIP)
		return
	}
	if settings.EnableIPWhitelist && !isIPInList(remoteIP, settings.IPWhitelist) {
		Print("[-] Connection from non-whitelisted IP %s rejected.", remoteIP)
		return
	}

	connInfo := &ActiveConnInfo{
		Writer:          conn,
		IP:              remoteIP,
		ConnKey:         connKey,
		FirstConnection: time.Now(),
		Status:          "握手",
	}
	connInfo.LastActive.Store(time.Now().Unix())
	AddActiveConn(connKey, connInfo)
	defer RemoveActiveConn(connKey)

	reader := bufio.NewReader(conn)
	forwardingStarted := false
	var initialData []byte
	var headersText string
	var finalDeviceID string
	var credential string

	for !forwardingStarted {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(settings.Timeout) * time.Second))
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF { Print("[-] Handshake read error from %s: %v", remoteIP, err) } else { Print("[-] Client %s closed connection during handshake.", remoteIP) }
			return
		}
		connInfo.LastActive.Store(time.Now().Unix())
		var headerBuilder strings.Builder
		_ = req.Header.Write(&headerBuilder)
		headersText = req.Method + " " + req.RequestURI + " " + req.Proto + "\r\n" + headerBuilder.String()
		body, _ := ioutil.ReadAll(req.Body)
		initialData = body

		credential = req.Header.Get("Sec-WebSocket-Key")
		
		var deviceInfo DeviceInfo
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
				_, _ = conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\n\r\n"))
				return
			}
			if !deviceInfo.Enabled {
				Print("[!] Auth Enabled: Device '%s' is disabled. Rejecting.", finalDeviceID)
				_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				return
			}
			expiry, err := time.Parse("2006-01-02", deviceInfo.Expiry)
			if err != nil || time.Now().After(expiry.Add(24*time.Hour)) {
				Print("[!] Auth Enabled: Device '%s' has expired. Rejecting.", finalDeviceID)
				_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
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
				_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				return
			}
		} else {
			if !found {
				finalDeviceID = remoteIP
			}
		}

		connInfo.DeviceID = finalDeviceID
		connInfo.Credential = credential
		
		ua := req.UserAgent()
		if settings.UAKeywordProbe != "" && strings.Contains(ua, settings.UAKeywordProbe) {
			Print("[*] Received probe from %s for device '%s'. Awaiting WS handshake.", remoteIP, finalDeviceID)
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nOK"))
			continue
		}
		if settings.UAKeywordWS != "" && strings.Contains(ua, settings.UAKeywordWS) {
			_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			connInfo.Status = "活跃"
			forwardingStarted = true
		} else {
			Print("[!] Unrecognized User-Agent from %s: '%s'. Rejecting.", remoteIP, ua)
			_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	targetHost := settings.DefaultTargetHost
	targetPort := settings.DefaultTargetPort
	if realHost := extractHeaderValue(headersText, "x-real-host"); realHost != "" {
		if host, portStr, err := net.SplitHostPort(realHost); err == nil {
			targetHost = host
			if p, err := strconv.Atoi(portStr); err == nil { targetPort = p }
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
	}

	if len(initialData) > 0 {
		_, err := targetConn.Write(initialData)
		if err != nil {
			Print("[!] Failed to write initial data to target: %v", err)
			return
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idleTimeout := time.Duration(settings.Timeout) * time.Second
	if idleTimeout < 90*time.Second {
		idleTimeout = 90 * time.Second
	}
	
	go func(innerCtx context.Context) {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				lastActive := connInfo.LastActive.Load()
				if time.Now().Unix()-lastActive > int64(idleTimeout.Seconds()) {
					Print("[-] [心跳] Kicking idle connection for device %s from %s (inactive for >%v)", finalDeviceID, remoteIP, idleTimeout)
					conn.Close()
					targetConn.Close()
					return
				}
			case <-innerCtx.Done():
				return
			}
		}
	}(ctx)

	var wg sync.WaitGroup
	wg.Add(2)
	
	go pipeTraffic(&wg, targetConn, conn, connInfo, credential, true, cancel)
	go pipeTraffic(&wg, conn, targetConn, connInfo, credential, false, cancel)
	
	wg.Wait()
}


// --- 后台管理面板相关函数 ---
func extractHeaderValue(text, name string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?mi)^%s:\s*(.+)$`, regexp.QuoteMeta(name)))
	m := re.FindStringSubmatch(text)
	if len(m) > 1 { return strings.TrimSpace(m[1]) }
	return ""
}
func isIPInList(ip string, list []string) bool {
	for _, item := range list {
		if item == ip { return true }
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
func manageSshUser(username, password, action string) (bool, string) { return false, "SSH user management is complex and platform-dependent, implementation omitted." }
const sessionCookieName = "wstunnel_session"
type Session struct { Username string; Expiry time.Time }
var (sessions = make(map[string]Session); sessionsLock sync.RWMutex)
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
	cfg.lock.RLock()
	storedPass, accountOk := cfg.Accounts[creds.Username]
	cfg.lock.RUnlock()
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
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: sessionToken, Expires: expiry, Path: "/", HttpOnly: true})
	sendJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		sessionsLock.Lock()
		delete(sessions, cookie.Value)
		sessionsLock.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
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
	if b < unit { return fmt.Sprintf("%d B", b) }
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
	if r.Body != nil {
		body, err := ioutil.ReadAll(r.Body)
		if err == nil && len(body) > 0 { _ = json.Unmarshal(body, &reqData) }
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
			if statusOrder[conns[i].Status] != statusOrder[conns[j].Status] { return statusOrder[conns[i].Status] < statusOrder[conns[j].Status] }
			return conns[i].FirstConnection.Before(conns[j].FirstConnection)
		})
		
		cfg.lock.RLock()
		devices := make(map[string]DeviceInfo)
		for k, v := range cfg.DeviceIDs {
			devices[k] = v
		}
		cfg.lock.RUnlock()

		resp := []APIConnectionResponse{}
		now := time.Now()
		for _, c := range conns {
			bytesSent := c.BytesSent.Load()
			bytesReceived := c.BytesReceived.Load()
			if c.Status == "活跃" {
				timeDelta := now.Sub(c.LastSpeedUpdateTime).Seconds()
				if timeDelta >= 2 {
					currentTotalBytes := bytesSent + bytesReceived
					bytesDelta := currentTotalBytes - c.LastTotalBytesForSpeed
					if timeDelta > 0 { c.CurrentSpeedBps = float64(bytesDelta) / timeDelta }
					c.LastSpeedUpdateTime = now
					c.LastTotalBytesForSpeed = currentTotalBytes
				}
			}
			var deviceInfo DeviceInfo
			var found bool
			if c.Credential != "" { deviceInfo, found = devices[c.Credential] }
			remainingStr := "无限制"
			if found && deviceInfo.LimitGB > 0 {
				var currentUsage int64
				if val, ok := deviceUsage.Load(c.Credential); ok { currentUsage = atomic.LoadInt64(val.(*int64)) }
				remainingBytes := int64(deviceInfo.LimitGB)*1024*1024*1024 - currentUsage
				if remainingBytes < 0 { remainingBytes = 0 }
				remainingStr = formatBytes(remainingBytes)
			}
			lastActiveTimestamp := c.LastActive.Load()
			lastActiveTime := time.Unix(lastActiveTimestamp, 0)
			resp = append(resp, APIConnectionResponse{DeviceID: c.DeviceID, Status: c.Status, SentStr: formatBytes(bytesSent), RcvdStr: formatBytes(bytesReceived), SpeedStr: fmt.Sprintf("%s/s", formatBytes(int64(c.CurrentSpeedBps))), RemainingStr: remainingStr, Expiry: deviceInfo.Expiry, IP: c.IP, FirstConn: c.FirstConnection.Format("15:04:05"), LastActive: lastActiveTime.Format("15:04:05"), ConnKey: c.ConnKey})
		}
		sendJSON(w, http.StatusOK, resp)
	case "/api/kick":
		connKey, _ := reqData["conn_key"].(string)
		if conn, ok := GetActiveConn(connKey); ok {
			_ = conn.Writer.Close()
			RemoveActiveConn(connKey)
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
		cfg.lock.RLock()
		devices := make(map[string]DeviceInfo)
		for k, v := range cfg.DeviceIDs {
			devices[k] = v
		}
		cfg.lock.RUnlock()
		sendJSON(w, http.StatusOK, devices)
	case "/api/settings":
		cfg.lock.RLock()
		settings := cfg.Settings
		cfg.lock.RUnlock()
		sendJSON(w, http.StatusOK, settings)
	case "/api/settings/toggle_device_auth":
		enable, _ := reqData["enable"].(bool)
		cfg.lock.Lock()
		cfg.Settings.EnableDeviceIDAuth = enable
		cfg.lock.Unlock()
		statusText := "开启"
		if !enable { statusText = "关闭" }
		sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": fmt.Sprintf("Device ID 验证已%s", statusText)})
	case "/api/ssh/create", "/api/ssh/delete":
		action := filepath.Base(r.URL.Path)
		username, _ := reqData["username"].(string)
		password, _ := reqData["password"].(string)
		success, message := manageSshUser(username, password, action)
		status := "ok"
		if !success { status = "error" }
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
		if val, ok := maxSessionsRaw.(float64); ok { ms = int(val) } else { ms = 1 }
		if ms < 1 { ms = 1 }
		
		cfg.lock.Lock()
		cfg.DeviceIDs[secWSKey] = DeviceInfo{FriendlyName: friendlyName, Expiry: exp, LimitGB: limit, UsedBytes: 0, MaxSessions: ms, Enabled: true}
		cfg.lock.Unlock()
		
		newUsage := int64(0)
		deviceUsage.Store(secWSKey, &newUsage)
		sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "设备信息已保存"})
	case "/device/set_status":
		secWSKey, ok1 := reqData["sec_ws_key"].(string)
		enabled, ok2 := reqData["enabled"].(bool)
		if !ok1 || !ok2 {
			sendJSON(w, http.StatusBadRequest, map[string]string{"status": "error", "message": "无效的请求"})
			return
		}
		cfg.lock.Lock()
		if info, ok := cfg.DeviceIDs[secWSKey]; ok {
			info.Enabled = enabled
			cfg.DeviceIDs[secWSKey] = info
			cfg.lock.Unlock()
			statusText := "启用"
			if !enabled { statusText = "禁用" }
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": fmt.Sprintf("设备 %s 已%s", info.FriendlyName, statusText)})
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
		sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "删除成功"})
	case "/device/reset_traffic":
		secWSKey, _ := reqData["sec_ws_key"].(string)
		if val, ok := deviceUsage.Load(secWSKey); ok { atomic.StoreInt64(val.(*int64), 0) }
		cfg.lock.Lock()
		if info, ok := cfg.DeviceIDs[secWSKey]; ok {
			info.UsedBytes = 0
			cfg.DeviceIDs[secWSKey] = info
		}
		cfg.lock.Unlock()
		sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "流量已重置"})
	case "/account/update":
		ou, _ := reqData["old_user"].(string)
		op, _ := reqData["old_pass"].(string)
		nu, _ := reqData["new_user"].(string)
		np, _ := reqData["new_pass"].(string)
		cfg.lock.RLock()
		storedPass, ok := cfg.Accounts[ou]
		cfg.lock.RUnlock()
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
		if ou != nu { delete(cfg.Accounts, ou) }
		cfg.Accounts[nu] = h
		cfg.lock.Unlock()
		sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "账号密码已更新，请重新登录！"})
	case "/settings/save":
		cfg.lock.RLock()
		oldPorts := []int{cfg.Settings.HTTPPort, cfg.Settings.TLSPort, cfg.Settings.StatusPort}
		cfg.lock.RUnlock()
		
		var newSettings Settings
		settingsBytes, _ := json.Marshal(reqData)
		_ = json.Unmarshal(settingsBytes, &newSettings)
		
		cfg.lock.Lock()
		cfg.Settings = newSettings
		cfg.lock.Unlock()
		
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
				cfg.SafeSave() 
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
			Print("[*] Settings updated in memory.")
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "设置已在内存中更新，将在10秒内自动保存到硬盘。"})
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
	log.SetOutput(ioutil.Discard)
	var err error
	adminPanelHTML, err = ioutil.ReadFile("admin.html")
	if err != nil {
		Print("[!] FATAL: admin.html not found: %v", err)
		os.Exit(1)
	}
	loginPanelHTML, err = ioutil.ReadFile("login.html")
	if err != nil {
		Print("[!] FATAL: login.html not found: %v", err)
		os.Exit(1)
	}
	Print("[*] WSTunnel-Go starting...")
	cfg := GetConfig()
	
	// 在获取 settings 后初始化 buffer pool
	cfg.lock.RLock()
	settings := cfg.Settings
	cfg.lock.RUnlock()
	initBufferPool(settings.BufferSize)

	InitMetrics()
	runPeriodicTasks()

	go func() {
		addr := fmt.Sprintf("0.0.0.0:%d", settings.HTTPPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			Print("[!] FATAL: Failed to listen on %s: %v", addr, err)
			os.Exit(1)
		}
		Print("[*] WS on %s", addr)
		for {
			conn, err := ln.Accept()
			if err != nil {
				Print("[!] WS accept error: %v", err)
				continue
			}
			go handleClient(conn, false)
		}
	}()
	if _, err := os.Stat(settings.CertFile); err == nil {
		if _, err := os.Stat(settings.KeyFile); err == nil {
			go func() {
				addr := fmt.Sprintf("0.0.0.0:%d", settings.TLSPort)
				cert, err := tls.LoadX509KeyPair(settings.CertFile, settings.KeyFile)
				if err != nil {
					Print("[!] Cert warning: %v. WSS server will not start.", err)
					return
				}
				ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err != nil {
					Print("[!] FATAL: Failed to listen on %s (TLS): %v", addr, err)
					return
				}
				Print("[*] WSS on %s", addr)
				for {
					conn, err := ln.Accept()
					if err != nil {
						Print("[!] WSS accept error: %v", err)
						continue
					}
					go handleClient(conn, true)
				}
			}()
		}
	} else {
		Print("[!] Cert/Key file not found. WSS server will not start.")
	}

	adminMux := http.NewServeMux()
	adminRootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value("user").(string)
		if !ok { user = "unknown" }
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
	Print("[*] Status on http://127.0.0.1:%d", settings.StatusPort)
	if err := http.ListenAndServe(adminAddr, adminMux); err != nil {
		Print("[!] FATAL: Failed to start admin server on %s: %v", err)
		os.Exit(1)
	}
}
