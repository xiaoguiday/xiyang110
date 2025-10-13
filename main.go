package main

import (
	// "bufio" // <-- 注意：如果你在其他地方没有用到，可以删除，但旧的 handleClient 用到了，所以我们保留
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/crypto/bcrypt" // <--- [集成点 1] 新增的 import
)


// =================================================================
// ---------------------- LOGGER (日志模块) -------------------------
// =================================================================

const logBufferSize = 200

type RingBuffer struct {
	mu     sync.RWMutex
	buffer []string
	head   int
}

func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		buffer: make([]string, capacity),
	}
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

func init() {
	logBuffer = NewRingBuffer(logBufferSize)
}

func Print(format string, v ...interface{}) {
	logBuffer.Add(fmt.Sprintf(format, v...))
}

// =================================================================
// ---------------------- CONFIG (配置模块) -------------------------
// =================================================================

var ConfigFile = "ws_config.json"

type Settings struct {
	HTTPPort                   int      `json:"http_port"`
	TLSPort                    int      `json:"tls_port"`
	StatusPort                 int      `json:"status_port"`
	DefaultTargetHost          string   `json:"default_target_host"`
	DefaultTargetPort          int      `json:"default_target_port"`
	BufferSize                 int      `json:"buffer_size"`
	Timeout                    int      `json:"timeout"`
	CertFile                   string   `json:"cert_file"`
	KeyFile                    string   `json:"key_file"`
	UAKeywordWS                string   `json:"ua_keyword_ws"`
	UAKeywordProbe             string   `json:"ua_keyword_probe"`
	AllowSimultaneousConnections bool   `json:"allow_simultaneous_connections"`
	DefaultExpiryDays          int      `json:"default_expiry_days"`
	DefaultLimitGB             int      `json:"default_limit_gb"`
	IPWhitelist                []string `json:"ip_whitelist"`
	IPBlacklist                []string `json:"ip_blacklist"`
	EnableIPWhitelist          bool     `json:"enable_ip_whitelist"`
	EnableIPBlacklist          bool     `json:"enable_ip_blacklist"`
	EnableDeviceIDAuth         bool     `json:"enable_device_id_auth"`
}

// <--- [集成点 2] 更新 DeviceInfo 结构体以支持新功能
type DeviceInfo struct {
	Expiry      string `json:"expiry"`
	LimitGB     int    `json:"limit_gb"`
	UsedBytes   int64  `json:"used_bytes"`
	SecWSKey    string `json:"sec_ws_key"`
	MaxSessions int    `json:"max_sessions"`
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
		HTTPPort: 80, TLSPort: 443, StatusPort: 9090,
		DefaultTargetHost: "127.0.0.1", DefaultTargetPort: 22,
		BufferSize: 8192, Timeout: 300,
		CertFile: "/etc/stunnel/certs/stunnel.pem", KeyFile: "/etc/stunnel/certs/stunnel.key",
		UAKeywordWS: "26.4.0", UAKeywordProbe: "1.0",
		AllowSimultaneousConnections: false,
		DefaultExpiryDays: 30, DefaultLimitGB: 100,
		EnableDeviceIDAuth: true,
	}
	c.Accounts = map[string]string{"admin": "admin"}
	c.DeviceIDs = make(map[string]DeviceInfo)

	data, err := ioutil.ReadFile(ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			Print("[*] %s not found, creating with default structure.", ConfigFile)
			return c.save()
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, c); err != nil {
		return fmt.Errorf("could not decode config file: %w. Please check its format", err)
	}
	return nil
}

func (c *Config) save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return ioutil.WriteFile(ConfigFile, data, 0644)
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

// <--- [集成点 3] 更新 GetDeviceIDs 方法以提供向后兼容性
func (c *Config) GetDeviceIDs() map[string]DeviceInfo {
	c.lock.RLock()
	defer c.lock.RUnlock()
	devices := make(map[string]DeviceInfo)
	for k, v := range c.DeviceIDs {
		if v.SecWSKey == "" {
			v.SecWSKey = ""
		}
		if v.MaxSessions == 0 {
			v.MaxSessions = 1
		}
		devices[k] = v
	}
	return devices
}

// <--- [集成点 4] 新增密码哈希相关函数
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}


// =================================================================
// ---------------------- METRICS (监控模块) ------------------------
// (此部分与旧代码完全相同，保持不变)
// =================================================================

type ActiveConnInfo struct {
	Writer                 net.Conn  `json:"-"`
	LastActive             time.Time `json:"last_active_time"`
	DeviceID               string    `json:"device_id"`
	FirstConnection        time.Time `json:"first_connection_time"`
	Status                 string    `json:"status"`
	IP                     string    `json:"ip"`
	BytesSent              int64     `json:"bytes_sent"`
	BytesReceived          int64     `json:"bytes_received"`
	ConnKey                string    `json:"conn_key"`
	LastSpeedUpdateTime    time.Time `json:"-"`
	LastTotalBytesForSpeed int64     `json:"-"`
	CurrentSpeedBps        float64   `json:"-"`
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
)

func InitMetrics() {
	cfg := GetConfig()
	devices := cfg.GetDeviceIDs()
	for id, info := range devices {
		deviceUsage.Store(id, info.UsedBytes)
	}
}

func AddActiveConn(key string, conn *ActiveConnInfo) {
	activeConns.Store(key, conn)
}

func RemoveActiveConn(key string) {
	activeConns.Delete(key)
}

func GetActiveConn(key string) (*ActiveConnInfo, bool) {
	if val, ok := activeConns.Load(key); ok {
		return val.(*ActiveConnInfo), true
	}
	return nil, false
}

func UpdateConnTraffic(key string, sent, received int64, deviceID string) {
	globalBytesSent += sent
	globalBytesReceived += received

	if conn, ok := GetActiveConn(key); ok {
		conn.BytesSent += sent
		conn.BytesReceived += received
		conn.LastActive = time.Now()
	}

	if deviceID != "" && deviceID != "unknown_device" {
		if val, ok := deviceUsage.Load(deviceID); ok {
			deviceUsage.Store(deviceID, val.(int64)+sent+received)
		} else {
			deviceUsage.Store(deviceID, sent+received)
		}
	}
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
}

func saveDeviceUsage() {
	cfg := GetConfig()
	cfg.lock.Lock()
	defer cfg.lock.Unlock()

	isDirty := false
	deviceUsage.Range(func(key, value interface{}) bool {
		id := key.(string)
		usage := value.(int64)
		if info, ok := cfg.DeviceIDs[id]; ok {
			if info.UsedBytes != usage {
				info.UsedBytes = usage
				cfg.DeviceIDs[id] = info
				isDirty = true
			}
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
	systemStatus.BytesSent = globalBytesSent
	systemStatus.BytesReceived = globalBytesReceived
}

// =================================================================
// ------------------ WS/WSS HANDLER (核心处理逻辑) ----------------
// (此部分与旧代码完全相同，保持不变)
// =================================================================

func handleClient(conn net.Conn, isTLS bool) {
	defer conn.Close()
	cfg := GetConfig()
	settings := cfg.GetSettings()
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
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

	tlsStr := ""
	if isTLS {
		tlsStr = " (TLS)"
	}
	Print("[+] Connection from %s%s", remoteIP, tlsStr)

	AddActiveConn(connKey, &ActiveConnInfo{
		Writer:          conn,
		LastActive:      time.Now(),
		FirstConnection: time.Now(),
		Status:          "握手",
		IP:              remoteIP,
		ConnKey:         connKey,
	})
	defer RemoveActiveConn(connKey)

	reader := bufio.NewReader(conn)
	forwardingStarted := false
	var initialData []byte
	var headersText string

	for !forwardingStarted {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(settings.Timeout) * time.Second))

		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				Print("[-] Handshake read error from %s: %v", remoteIP, err)
			} else {
				Print("[-] Client %s closed connection during handshake.", remoteIP)
			}
			return
		}

		var headerBuilder strings.Builder
		_ = req.Header.Write(&headerBuilder)
		headersText = req.Method + " " + req.RequestURI + " " + req.Proto + "\r\n" + headerBuilder.String()

		body, _ := ioutil.ReadAll(req.Body)
		initialData = body

		deviceID := req.Header.Get("x-device-id")
		if deviceID == "" {
			deviceID = req.Header.Get("device-id")
		}

		finalDeviceID := deviceID
		if finalDeviceID == "" {
			finalDeviceID = "unknown_device"
		}

		if connInfo, ok := GetActiveConn(connKey); ok {
			connInfo.DeviceID = finalDeviceID
		}

		if settings.EnableDeviceIDAuth {
			if deviceID == "" {
				Print("[!] Auth Enabled: No device ID from %s. Rejecting.", remoteIP)
				_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				return
			}

			deviceInfo, ok := cfg.GetDeviceIDs()[deviceID]
			if !ok {
				Print("[!] Auth Enabled: Invalid device ID '%s' from %s. Rejecting.", deviceID, remoteIP)
				_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				return
			}

			expiry, err := time.Parse("2006-01-02", deviceInfo.Expiry)
			if err != nil || time.Now().After(expiry.Add(24*time.Hour)) {
				Print("[!] Auth Enabled: Device ID %s has expired. Rejecting.", deviceID)
				_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				return
			}

			usage, _ := deviceUsage.LoadOrStore(deviceID, int64(0))
			if deviceInfo.LimitGB > 0 && usage.(int64) >= int64(deviceInfo.LimitGB)*1024*1024*1024 {
				Print("[!] Auth Enabled: Traffic limit reached for %s. Rejecting.", deviceID)
				_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				return
			}
		}

		ua := req.UserAgent()

		if settings.UAKeywordProbe != "" && strings.Contains(ua, settings.UAKeywordProbe) {
			Print("[*] Received probe from %s for device '%s'. Awaiting WS handshake.", remoteIP, finalDeviceID)
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nOK"))
			continue
		}

		if settings.UAKeywordWS != "" && strings.Contains(ua, settings.UAKeywordWS) {
			Print("[*] Received WebSocket handshake from %s for device '%s'.", remoteIP, finalDeviceID)

			if !settings.AllowSimultaneousConnections && finalDeviceID != "unknown_device" {
				var existingConnKey string
				activeConns.Range(func(key, value interface{}) bool {
					c := value.(*ActiveConnInfo)
					if c.DeviceID == finalDeviceID && c.ConnKey != connKey {
						existingConnKey = c.ConnKey
						return false
					}
					return true
				})
				if existingConnKey != "" {
					Print("[!] WS Check: Simultaneous connection rejected for device %s. Blocked by: %s", finalDeviceID, existingConnKey)
					_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
					return
				}
			}

			_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			if connInfo, ok := GetActiveConn(connKey); ok {
				connInfo.Status = "活跃"
			}
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
			if p, err := strconv.Atoi(portStr); err == nil {
				targetPort = p
			}
		} else {
			targetHost = realHost
		}
	}

	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	Print("[*] Tunneling %s -> %s", remoteIP, targetAddr)

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
		_, _ = targetConn.Write(initialData)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)

	go pipeTraffic(ctx, conn, targetConn, &wg, connKey, true)
	go pipeTraffic(ctx, targetConn, conn, &wg, connKey, false)

	wg.Wait()
	cancel()
	Print("[-] Closed connection for %s", remoteIP)
}

func pipeTraffic(ctx context.Context, dst, src net.Conn, wg *sync.WaitGroup, connKey string, isUpload bool) {
	defer wg.Done()

	cfg := GetConfig()
	buffer := make([]byte, cfg.GetSettings().BufferSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := src.Read(buffer)
			if n > 0 {
				_, writeErr := dst.Write(buffer[:n])
				if writeErr != nil {
					return
				}

				connInfo, ok := GetActiveConn(connKey)
				if !ok {
					return
				}

				if isUpload {
					UpdateConnTraffic(connKey, int64(n), 0, connInfo.DeviceID)
				} else {
					UpdateConnTraffic(connKey, 0, int64(n), connInfo.DeviceID)
				}
			}
			if err != nil {
				if tcpConn, ok := dst.(*net.TCPConn); ok {
					_ = tcpConn.CloseWrite()
				}
				return
			}
		}
	}
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

// =================================================================
// ------------------ SSH USER MGMT (SSH用户管理) ------------------
// (此部分与旧代码完全相同，保持不变)
// =================================================================

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

func manageSshUser(username, password, action string) (bool, string) {
	if os.Geteuid() != 0 {
		return false, "此操作需要 root 权限。"
	}
	if !regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`).MatchString(username) {
		return false, "无效的用户名。请使用小写字母、数字、下划线或连字符。"
	}

	sshdConfigPath := "/etc/ssh/sshd_config"
	startMarker := fmt.Sprintf("# WSSUSER_BLOCK_START_%s", username)
	endMarker := fmt.Sprintf("# WSSUSER_BLOCK_END_%s", username)

	cleanSshdConfig := func() error {
		content, err := ioutil.ReadFile(sshdConfigPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		lines := strings.Split(string(content), "\n")
		var newLines []string
		inBlock := false
		for _, line := range lines {
			if strings.Contains(line, startMarker) {
				inBlock = true
				continue
			}
			if strings.Contains(line, endMarker) {
				inBlock = false
				continue
			}
			if !inBlock {
				newLines = append(newLines, line)
			}
		}
		return ioutil.WriteFile(sshdConfigPath, []byte(strings.Join(newLines, "\n")), 0644)
	}

	restartSshd := func() (bool, string) {
		success, msg := runCommand("systemctl", "restart", "sshd")
		if !success {
			success, msg = runCommand("systemctl", "restart", "ssh")
		}
		return success, msg
	}

	if action == "delete" {
		if err := cleanSshdConfig(); err != nil {
			return false, fmt.Sprintf("清理 sshd_config 失败: %v", err)
		}

		cmd := exec.Command("id", username)
		if cmd.Run() == nil {
			delSuccess, msg := runCommand("userdel", "-r", username)
			if !delSuccess {
				return false, fmt.Sprintf("删除用户失败: %s", msg)
			}
		}

		sshdRestartSuccess, msg := restartSshd()
		if !sshdRestartSuccess {
			return false, fmt.Sprintf("SSHD/SSH 重启失败: %s", msg)
		}
		return true, fmt.Sprintf("用户 %s 及相关配置已成功删除。", username)
	}

	if action == "create" {
		if password == "" {
			return false, "创建用户时必须提供密码。"
		}
		if err := cleanSshdConfig(); err != nil {
			return false, fmt.Sprintf("清理旧 sshd_config 失败: %v", err)
		}

		cmd := exec.Command("id", username)
		if cmd.Run() != nil {
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

		f, err := os.OpenFile(sshdConfigPath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return false, fmt.Sprintf("打开 sshd_config 失败: %v", err)
		}

		newBlock := fmt.Sprintf("\n%s\nMatch User %s Address 127.0.0.1,::1\n    PasswordAuthentication yes\n    PermitTTY yes\n    AllowTcpForwarding yes\nMatch User %s Address *,!127.0.0.1,!::1\n    PasswordAuthentication no\n    PermitTTY no\n    AllowTcpForwarding no\n%s\n", startMarker, username, username, endMarker)
		_, _ = f.WriteString(newBlock)
		f.Close()

		sshdRestartSuccess, msg := restartSshd()
		if !sshdRestartSuccess {
			return false, fmt.Sprintf("SSHD/SSH 重启失败: %s", msg)
		}
		return true, fmt.Sprintf("SSH 用户 '%s' 已成功创建/更新。", username)
	}

	return false, "未知操作。"
}

// =================================================================
// ------------------ ADMIN PANEL (Web管理面板) --------------------
// =================================================================

func basicAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := GetConfig()
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		
		// <--- [集成点 5] 更新 basicAuth 以支持哈希密码
		cfg.lock.RLock()
		storedPass, accountOk := cfg.Accounts[user]
		cfg.lock.RUnlock()

		if !accountOk {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		
		valid := false
		if len(storedPass) >= 60 && strings.HasPrefix(storedPass, "$2a$") {
			valid = checkPasswordHash(pass, storedPass)
		} else {
			valid = (pass == storedPass)
		}

		if !valid {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		
		ctx := context.WithValue(r.Context(), "user", user)
		handler(w, r.WithContext(ctx))
	}
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
	DeviceID      string `json:"device_id"`
	Status        string `json:"status"`
	SentStr       string `json:"sent_str"`
	RcvdStr       string `json:"rcvd_str"`
	SpeedStr      string `json:"speed_str"`
	RemainingStr  string `json:"remaining_str"`
	Expiry        string `json:"expiry"`
	IP            string `json:"ip"`
	FirstConn     string `json:"first_conn"`
	LastActive    string `json:"last_active"`
	ConnKey       string `json:"conn_key"`
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	cfg := GetConfig()
	var reqData map[string]interface{}
	if r.Body != nil {
		body, err := ioutil.ReadAll(r.Body)
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

		resp := []APIConnectionResponse{}
		now := time.Now()

		for _, c := range conns {
			if c.Status == "活跃" {
				timeDelta := now.Sub(c.LastSpeedUpdateTime).Seconds()
				if timeDelta >= 2 {
					currentTotalBytes := c.BytesSent + c.BytesReceived
					bytesDelta := currentTotalBytes - c.LastTotalBytesForSpeed
					if timeDelta > 0 {
						c.CurrentSpeedBps = float64(bytesDelta) / timeDelta
					}
					c.LastSpeedUpdateTime = now
					c.LastTotalBytesForSpeed = currentTotalBytes
				}
			}

			remainingStr := "无限制"
			deviceInfo, ok := cfg.GetDeviceIDs()[c.DeviceID]
			if ok && deviceInfo.LimitGB > 0 {
				usage, _ := deviceUsage.Load(c.DeviceID)
				remainingBytes := int64(deviceInfo.LimitGB)*1024*1024*1024 - usage.(int64)
				if remainingBytes < 0 {
					remainingBytes = 0
				}
				remainingStr = formatBytes(remainingBytes)
			}

			resp = append(resp, APIConnectionResponse{
				DeviceID:     c.DeviceID, Status: c.Status,
				SentStr:      formatBytes(c.BytesSent), RcvdStr: formatBytes(c.BytesReceived),
				SpeedStr:     fmt.Sprintf("%s/s", formatBytes(int64(c.CurrentSpeedBps))),
				RemainingStr: remainingStr, Expiry: deviceInfo.Expiry, IP: c.IP,
				FirstConn:    c.FirstConnection.Format("15:04:05"), LastActive: c.LastActive.Format("15:04:05"),
				ConnKey:      c.ConnKey,
			})
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

	case "/api/clear":
		connKey, _ := reqData["conn_key"].(string)
		RemoveActiveConn(connKey)
		sendJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	case "/api/device_usage":
		usageMap := make(map[string]int64)
		deviceUsage.Range(func(key, value interface{}) bool {
			usageMap[key.(string)] = value.(int64)
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

// <--- [集成点 6] 使用新的 handleAdminPost 函数替换旧的
func handleAdminPost(w http.ResponseWriter, r *http.Request) {
	cfg := GetConfig()
	var reqData map[string]interface{}
	if json.NewDecoder(r.Body).Decode(&reqData) != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"status": "error", "message": "无效的JSON格式"})
		return
	}

	switch r.URL.Path {
	case "/device/add":
		did, _ := reqData["device_id"].(string)
		exp, _ := reqData["expiry"].(string)
		limitStr, _ := reqData["limit_gb"].(string)
		secWSKey, _ := reqData["sec_ws_key"].(string)
		maxSessionsRaw, hasMaxSessions := reqData["max_sessions"]
		limit, _ := strconv.Atoi(limitStr)
		ms := 1
		if hasMaxSessions {
			switch v := maxSessionsRaw.(type) {
			case float64:
				ms = int(v)
			case string:
				ms, _ = strconv.Atoi(v)
			}
			if ms < 0 || ms > 5 {
				ms = 1
			}
		}
		cfg.lock.Lock()
		currentUsage := int64(0)
		if oldInfo, ok := cfg.DeviceIDs[did]; ok {
			currentUsage = oldInfo.UsedBytes
		}
		cfg.DeviceIDs[did] = DeviceInfo{
			Expiry:      exp,
			LimitGB:     limit,
			UsedBytes:   currentUsage,
			SecWSKey:    secWSKey,
			MaxSessions: ms,
		}
		cfg.lock.Unlock()
		if err := cfg.SafeSave(); err != nil {
			sendJSON(w, http.StatusOK, map[string]string{"status": "error", "message": err.Error()})
		} else {
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "保存成功"})
		}

	case "/device/delete":
		did, _ := reqData["device_id"].(string)
		cfg.lock.Lock()
		delete(cfg.DeviceIDs, did)
		cfg.lock.Unlock()
		deviceUsage.Delete(did)
		if err := cfg.SafeSave(); err != nil {
			sendJSON(w, http.StatusOK, map[string]string{"status": "error", "message": err.Error()})
		} else {
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "删除成功"})
		}

	case "/device/reset_traffic":
		did, _ := reqData["device_id"].(string)
		deviceUsage.Store(did, int64(0))
		cfg.lock.Lock()
		if info, ok := cfg.DeviceIDs[did]; ok {
			info.UsedBytes = 0
			cfg.DeviceIDs[did] = info
		}
		cfg.lock.Unlock()
		if err := cfg.SafeSave(); err != nil {
			sendJSON(w, http.StatusOK, map[string]string{"status": "error", "message": err.Error()})
		} else {
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "流量已重置"})
		}
		
	case "/account/update":
		ou, _ := reqData["old_user"].(string)
		op, _ := reqData["old_pass"].(string)
		nu, _ := reqData["new_user"].(string)
		np, _ := reqData["new_pass"].(string)

		cfg.lock.Lock()
		storedPass, ok := cfg.Accounts[ou]
		cfg.lock.Unlock()
		
		valid := false
		if len(storedPass) >= 60 && strings.HasPrefix(storedPass, "$2a$") {
			valid = checkPasswordHash(op, storedPass)
		} else {
			valid = (op == storedPass)
		}

		if !ok || !valid {
			sendJSON(w, http.StatusOK, map[string]string{"status": "error", "message": "原账号或密码错误"})
			return
		}
		
		h, err := hashPassword(np)
		if err != nil {
			sendJSON(w, http.StatusOK, map[string]string{"status": "error", "message": "密码加密失败"})
			return
		}
		
		cfg.lock.Lock()
		delete(cfg.Accounts, ou)
		cfg.Accounts[nu] = h
		cfg.lock.Unlock()
		
		if err := cfg.SafeSave(); err != nil {
			sendJSON(w, http.StatusOK, map[string]string{"status": "error", "message": err.Error()})
		} else {
			sendJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "修改成功"})
		}

	case "/settings/save":
		oldSettings := cfg.GetSettings()
		oldPorts := []int{oldSettings.HTTPPort, oldSettings.TLSPort, oldSettings.StatusPort}

		var newSettings Settings
		settingsBytes, _ := json.Marshal(reqData)
		_ = json.Unmarshal(settingsBytes, &newSettings)

		if wl, ok := reqData["ip_whitelist"].(string); ok {
			newSettings.IPWhitelist = strings.Split(wl, ",")
		}
		if bl, ok := reqData["ip_blacklist"].(string); ok {
			newSettings.IPBlacklist = strings.Split(bl, ",")
		}

		cfg.lock.Lock()
		cfg.Settings = newSettings
		cfg.lock.Unlock()

		if err := cfg.SafeSave(); err != nil {
			sendJSON(w, http.StatusOK, map[string]string{"status": "error", "message": fmt.Sprintf("保存失败: %v", err)})
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


func handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	user := r.Context().Value("user").(string)

	systemStatusMutex.RLock()
	activeCount := 0
	activeConns.Range(func(key, value interface{}) bool {
		if value.(*ActiveConnInfo).Status == "活跃" {
			activeCount++
		}
		return true
	})

	memStr := "N/A"
	if systemStatus.MemTotal > 0 {
		memStr = fmt.Sprintf("%.1f/%.1f GB (%.1f%%)",
			float64(systemStatus.MemUsed)/1073741824,
			float64(systemStatus.MemTotal)/1073741824,
			systemStatus.MemPercent)
	}

	html := string(adminPanelHTML)
	html = strings.Replace(html, "__USER__", user, -1)
	html = strings.Replace(html, "__ACTIVE_COUNT__", strconv.Itoa(activeCount), -1)
	html = strings.Replace(html, "__GLOBAL_SENT__", formatBytes(systemStatus.BytesSent), -1)
	html = strings.Replace(html, "__GLOBAL_RECEIVED__", formatBytes(systemStatus.BytesReceived), -1)
	html = strings.Replace(html, "__UPTIME__", systemStatus.Uptime, -1)
	html = strings.Replace(html, "__CPU__", fmt.Sprintf("%.1f%%", systemStatus.CPUPercent), -1)
	html = strings.Replace(html, "__CPU_CORES__", strconv.Itoa(systemStatus.CPUCores), -1)
	html = strings.Replace(html, "__MEM__", memStr, -1)
	systemStatusMutex.RUnlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

// =================================================================
// ---------------------- MAIN (主函数) ---------------------------
// (此部分与旧代码完全相同，保持不变)
// =================================================================

func main() {
	log.SetOutput(ioutil.Discard)

	var err error
	adminPanelHTML, err = ioutil.ReadFile("admin.html")
	if err != nil {
		Print("[!] FATAL: admin.html not found in the current directory: %v", err)
		Print("[!] Please make sure 'admin.html' is in the same folder as the executable.")
		os.Exit(1)
	}

	Print("[*] WSTunnel-Go starting...")
	cfg := GetConfig()
	InitMetrics()
	settings := cfg.GetSettings()
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
	adminMux.HandleFunc("/", basicAuth(handleAdminPage))
	adminMux.HandleFunc("/api/", basicAuth(handleAPI))
	adminMux.HandleFunc("/device/", basicAuth(handleAdminPost))
	adminMux.HandleFunc("/account/", basicAuth(handleAdminPost))
	adminMux.HandleFunc("/settings/", basicAuth(handleAdminPost))
	adminMux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})

	adminAddr := fmt.Sprintf("0.0.0.0:%d", settings.StatusPort)
	Print("[*] Status on http://127.0.0.1:%d", settings.StatusPort)
	if err := http.ListenAndServe(adminAddr, adminMux); err != nil {
		Print("[!] FATAL: Failed to start admin server on %s: %v", adminAddr, err)
		os.Exit(1)
	}
}
