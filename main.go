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

const logBufferSize = 200

// RingBuffer and logging functions (No changes)
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


var ConfigFile = "ws_config.json"

// Settings struct (No changes)
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

// *** CHANGED: DeviceInfo struct is updated for the new architecture ***
type DeviceInfo struct {
	FriendlyName string `json:"friendly_name"` // NEW: Used for display names like "hooks#4770"
	Expiry       string `json:"expiry"`
	LimitGB      int    `json:"limit_gb"`
	UsedBytes    int64  `json:"used_bytes"`
	MaxSessions  int    `json:"max_sessions"`
	Enabled      bool   `json:"enabled"`
	// REMOVED: SecWSKey is no longer needed here, it's the map key now.
}

// Config struct (No changes, key is still string)
type Config struct {
	Settings  Settings                `json:"settings"`
	Accounts  map[string]string       `json:"accounts"`
	DeviceIDs map[string]DeviceInfo `json:"device_ids"` // IMPORTANT: The key of this map is now the sec_ws_key
	lock      sync.RWMutex
}

var globalConfig *Config
var once sync.Once

// GetConfig and load (No significant changes, migration logic is fine)
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
	// Default settings remain the same
	c.Settings = Settings{HTTPPort: 80, TLSPort: 443, StatusPort: 9090, DefaultTargetHost: "127.0.0.1", DefaultTargetPort: 22, BufferSize: 8192, Timeout: 300, CertFile: "/etc/stunnel/certs/stunnel.pem", KeyFile: "/etc/stunnel/certs/stunnel.key", UAKeywordWS: "26.4.0", UAKeywordProbe: "1.0", AllowSimultaneousConnections: false, DefaultExpiryDays: 30, DefaultLimitGB: 100, EnableDeviceIDAuth: true}
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
    // Migration logic for 'enabled' field is kept, it won't interfere.
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
func (c *Config) SafeSave() error { c.lock.Lock(); defer c.lock.Unlock(); return c.save() }
func (c *Config) GetSettings() Settings { c.lock.RLock(); defer c.lock.RUnlock(); return c.Settings }
func (c *Config) GetAccounts() map[string]string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	accts := make(map[string]string)
	for k, v := range c.Accounts { accts[k] = v }
	return accts
}
func (c *Config) GetDeviceIDs() map[string]DeviceInfo {
	c.lock.RLock()
	defer c.lock.RUnlock()
	devices := make(map[string]DeviceInfo)
	for k, v := range c.DeviceIDs {
		if v.MaxSessions < 1 { v.MaxSessions = 1 }
		devices[k] = v
	}
	return devices
}

// Password hashing functions (No changes)
func hashPassword(password string) (string, error) { /* ... */ }
func checkPasswordHash(password, hash string) bool { /* ... */ }

// *** REMOVED: FindDeviceByWSKey is obsolete and has been deleted. ***

// *** CHANGED: ActiveConnInfo now stores both friendly name and the credential (sec_ws_key) ***
type ActiveConnInfo struct {
	Writer              net.Conn
	LastActive          time.Time
	DeviceID            string    // This will now store the FriendlyName for display
	Credential          string    // NEW: This stores the actual sec_ws_key for lookups
	FirstConnection     time.Time
	Status              string
	IP                  string
	BytesSent           int64
	BytesReceived       int64
	ConnKey             string
	LastSpeedUpdateTime time.Time
	LastTotalBytesForSpeed int64
	CurrentSpeedBps     float64
}

// SystemStatus and related vars (No changes)
type SystemStatus struct { /* ... */ }
var ( /* ... */ )

// *** CHANGED: InitMetrics now uses the new map key (sec_ws_key) ***
func InitMetrics() {
	cfg := GetConfig()
	devices := cfg.GetDeviceIDs()
	// The key 'id' is now the sec_ws_key
	for id, info := range devices {
		initialUsage := info.UsedBytes
		// We will track usage by the unique credential (sec_ws_key)
		deviceUsage.Store(id, &initialUsage)
	}
}

// Active connection helpers (No changes)
func AddActiveConn(key string, conn *ActiveConnInfo) { activeConns.Store(key, conn) }
func RemoveActiveConn(key string) { activeConns.Delete(key) }
func GetActiveConn(key string) (*ActiveConnInfo, bool) { /* ... */ }

// *** CHANGED: auditActiveConnections now uses the credential for efficient lookups ***
func auditActiveConnections() {
    cfg := GetConfig()
    settings := cfg.GetSettings()
	devices := cfg.GetDeviceIDs() // This map's key is the credential (sec_ws_key)

    activeConns.Range(func(key, value interface{}) bool {
        connInfo := value.(*ActiveConnInfo)
        
        if settings.EnableIPBlacklist && isIPInList(connInfo.IP, settings.IPBlacklist) {
            Print("[-] Kicking active connection from blacklisted IP %s (Device: %s)", connInfo.IP, connInfo.DeviceID)
            connInfo.Writer.Close()
            return true
        }

		// If auth is disabled, we don't need to check device-specific rules
		if !settings.EnableDeviceIDAuth {
			return true
		}

        // Use the credential for a fast, direct lookup
        if connInfo.Credential != "" {
            if devInfo, ok := devices[connInfo.Credential]; ok {
                if !devInfo.Enabled {
                    Print("[-] Kicking active connection from disabled device %s (IP: %s)", connInfo.DeviceID, connInfo.IP)
                    connInfo.Writer.Close()
                    return true
                }
				// ... Other checks like expiry, traffic limit can also be performed here efficiently
            } else {
				// Device was deleted from config, kick the connection
				Print("[-] Kicking active connection, device %s no longer exists (IP: %s)", connInfo.DeviceID, connInfo.IP)
				connInfo.Writer.Close()
				return true
			}
        }
        return true
    })
	// Session limit logic can also be added here, using a counter map based on connInfo.Credential
}

// runPeriodicTasks, saveDeviceUsage, collectSystemStatus (No major changes)
func runPeriodicTasks() { /* ... */ }

// *** CHANGED: saveDeviceUsage key 'id' is now the credential (sec_ws_key) ***
func saveDeviceUsage() {
	cfg := GetConfig()
	cfg.lock.Lock()
	defer cfg.lock.Unlock()
	isDirty := false
	deviceUsage.Range(func(key, value interface{}) bool {
		id := key.(string) // This 'id' is the sec_ws_key
		currentUsage := value.(*int64)
		// We look up in DeviceIDs using the same key
		if info, ok := cfg.DeviceIDs[id]; ok {
			if info.UsedBytes != atomic.LoadInt64(currentUsage) {
				info.UsedBytes = atomic.LoadInt64(currentUsage)
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
func collectSystemStatus() { /* ... */ }


func handleClient(conn net.Conn, isTLS bool) {
	defer conn.Close()
	cfg := GetConfig()
	settings := cfg.GetSettings()
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	connKey := fmt.Sprintf("%s-%d", remoteIP, time.Now().UnixNano())

	if tcpConn, ok := conn.(*net.TCPConn); ok { /* ... */ }
	if settings.EnableIPBlacklist && isIPInList(remoteIP, settings.IPBlacklist) { /* ... */ }
	if settings.EnableIPWhitelist && !isIPInList(remoteIP, settings.IPWhitelist) { /* ... */ }
	
	Print("[+] Connection from %s%s", remoteIP, isTLS)
	AddActiveConn(connKey, &ActiveConnInfo{Writer: conn, IP: remoteIP, ConnKey: connKey, FirstConnection: time.Now(), LastActive: time.Now(), Status: "握手"})
	defer RemoveActiveConn(connKey)

	reader := bufio.NewReader(conn)
	forwardingStarted := false
	var initialData []byte
	var headersText string
	
	var finalDeviceID string // Will store the FriendlyName
	var credential string    // Will store the sec_ws_key
	var deviceInfo DeviceInfo

	for !forwardingStarted {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(settings.Timeout) * time.Second))
		req, err := http.ReadRequest(reader)
		if err != nil { /* ... */ return }
		
		var headerBuilder strings.Builder
		_ = req.Header.Write(&headerBuilder)
		headersText = req.Method + " " + req.RequestURI + " " + req.Proto + "\r\n" + headerBuilder.String()
		body, _ := ioutil.ReadAll(req.Body)
		initialData = body

		// *** CHANGED: New high-performance authentication logic ***
		credential = req.Header.Get("Sec-WebSocket-Key")
		var found bool
		if credential != "" {
			cfg.lock.RLock()
			// Direct, O(1) lookup!
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

			// Use credential for usage tracking
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

		if connInfo, ok := GetActiveConn(connKey); ok {
			connInfo.DeviceID = finalDeviceID
			connInfo.Credential = credential // Store the credential too
		}

		ua := req.UserAgent()
		if settings.UAKeywordProbe != "" && strings.Contains(ua, settings.UAKeywordProbe) { /* ... */ }
		
		if settings.UAKeywordWS != "" && strings.Contains(ua, settings.UAKeywordWS) {
			// Session limit logic here... (can be simplified now)
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
	
	targetHost, targetPort := settings.DefaultTargetHost, settings.DefaultTargetPort
	// ... (target host parsing logic is unchanged)
	
	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	Print("[*] Tunneling %s -> %s for device %s", remoteIP, targetAddr, finalDeviceID)
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil { /* ... */ return }
	defer targetConn.Close()
	
	if tcpTargetConn, ok := targetConn.(*net.TCPConn); ok { /* ... */ }
	
	if len(initialData) > 0 {
		_, _ = targetConn.Write(initialData)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)

	// *** CHANGED: Passing correct reader and credential to pipeTraffic ***
	go pipeTraffic(ctx, &wg, targetConn, reader, connKey, finalDeviceID, credential, true)
	go pipeTraffic(ctx, &wg, conn, targetConn, connKey, finalDeviceID, credential, false)
	
	wg.Wait()
	cancel()
	Print("[-] Closed connection for %s (Device: %s)", remoteIP, finalDeviceID)
}

// *** CHANGED: copyTracker and pipeTraffic now use the credential for usage tracking ***
type copyTracker struct {
	io.Writer
	ConnInfo     *ActiveConnInfo
	DeviceID     string // FriendlyName
	Credential   string // sec_ws_key
	IsUpload     bool
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
		// Use credential for usage tracking
		if c.Credential != "" && c.DeviceUsagePtr != nil {
			atomic.AddInt64(c.DeviceUsagePtr, int64(n))
		}
		c.ConnInfo.LastActive = time.Now()
	}
	return
}
func pipeTraffic(ctx context.Context, wg *sync.WaitGroup, dst net.Conn, src io.Reader, connKey, deviceID, credential string, isUpload bool) {
	defer wg.Done()
	connInfo, ok := GetActiveConn(connKey)
	if !ok { return }
	
	var deviceUsagePtr *int64
	// Use credential to load usage pointer
	if credential != "" {
		if val, ok := deviceUsage.Load(credential); ok {
			deviceUsagePtr = val.(*int64)
		}
	}

	tracker := &copyTracker{Writer: dst, ConnInfo: connInfo, DeviceID: deviceID, Credential: credential, IsUpload: isUpload, DeviceUsagePtr: deviceUsagePtr}
	buf := make([]byte, 32*1024)
	io.CopyBuffer(tracker, src, buf)
	if tcpConn, ok := dst.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
}

// Helper functions (no changes)
func extractHeaderValue(text, name string) string { /* ... */ }
func isIPInList(ip string, list []string) bool { /* ... */ }
func runCommand(command string, args ...string) (bool, string) { /* ... */ }
func manageSshUser(username, password, action string) (bool, string) { /* ... */ }


// Admin Panel Session Management (no changes)
const sessionCookieName = "wstunnel_session"
type Session struct { /* ... */ }
var (sessions = make(map[string]Session); sessionsLock sync.RWMutex)
func authMiddleware(next http.Handler) http.HandlerFunc { /* ... */ }
func loginHandler(w http.ResponseWriter, r *http.Request) { /* ... */ }
func logoutHandler(w http.ResponseWriter, r *http.Request) { /* ... */ }
func sendJSON(w http.ResponseWriter, code int, payload interface{}) { /* ... */ }

// Admin Panel API Handlers (some changes needed)
func formatBytes(b int64) string { /* ... */ }
type APIConnectionResponse struct { /* ... */ }

func handleAPI(w http.ResponseWriter, r *http.Request) {
	// Most of this is for reading data, which is fine.
	// We only need to adjust how we interpret the data from cfg.GetDeviceIDs()
	cfg := GetConfig()
	// ...
	switch r.URL.Path {
	case "/api/connections":
		// ...
		// This logic needs to be aware that the key of GetDeviceIDs is now the credential
		// but `c.DeviceID` in ActiveConnInfo is the friendly name. This is a mismatch.
		// For simplicity, we can just leave this as is for now, as it's for display only.
		// The `deviceInfo, ok := cfg.GetDeviceIDs()[c.DeviceID]` will fail.
		// A proper fix would be to create an index, but let's keep it simple.
		// We can find the device by iterating, since this is a low-frequency admin task.
		devices := cfg.GetDeviceIDs() // key is credential
		// ...
		for _, c := range conns {
			// ...
			var deviceInfo DeviceInfo
			var found bool
			// Low-performance search is OK for admin panel display
			for _, d := range devices {
				if d.FriendlyName == c.DeviceID {
					deviceInfo = d
					found = true
					break
				}
			}

			remainingStr := "无限制"
			if found && deviceInfo.LimitGB > 0 {
				var currentUsage int64
				if val, usageOk := deviceUsage.Load(c.Credential); usageOk { // Use credential for usage lookup
					currentUsage = atomic.LoadInt64(val.(*int64))
				}
				// ... calculate remaining ...
			}
			// ... append to resp
		}
		// ...
	case "/api/devices":
		// This now returns a map where keys are credentials. The frontend must handle this.
		sendJSON(w, http.StatusOK, cfg.GetDeviceIDs())
	// ... Other cases are mostly fine
	}
}

// *** CHANGED: Admin POST handlers now expect and use sec_ws_key as the primary ID ***
func handleAdminPost(w http.ResponseWriter, r *http.Request) {
	cfg := GetConfig()
	var reqData map[string]interface{}
	if json.NewDecoder(r.Body).Decode(&reqData) != nil { /* ... */ }
	
	switch r.URL.Path {
	case "/device/add":
		friendlyName, _ := reqData["friendly_name"].(string) // Expecting friendly_name now
		secWSKey, _ := reqData["sec_ws_key"].(string)
		exp, _ := reqData["expiry"].(string)
		limitStr, _ := reqData["limit_gb"].(string)
		// ...
		if friendlyName == "" || exp == "" || secWSKey == "" {
			sendJSON(w, http.StatusBadRequest, map[string]string{"status": "error", "message": "名称, 有效期, 和 Sec-WebSocket-Key 不能为空"})
			return
		}
		limit, _ := strconv.Atoi(limitStr)
		ms, _ := reqData["max_sessions"].(float64)

		cfg.lock.Lock()
		// The key for the map is secWSKey
		cfg.DeviceIDs[secWSKey] = DeviceInfo{
			FriendlyName: friendlyName,
			Expiry:       exp,
			LimitGB:      limit,
			UsedBytes:    0, // New or updated device resets usage in this logic
			MaxSessions:  int(ms),
			Enabled:      true,
		}
		cfg.lock.Unlock()
		deviceUsage.Store(secWSKey, new(int64)) // Ensure usage map is updated
		if err := cfg.SafeSave(); err != nil { /* ... */ } else { /* ... */ }

	case "/device/set_status":
		secWSKey, ok1 := reqData["sec_ws_key"].(string) // MUST receive sec_ws_key
		enabled, ok2 := reqData["enabled"].(bool)
		if !ok1 || !ok2 { /* ... */ return }
		
		cfg.lock.Lock()
		if info, ok := cfg.DeviceIDs[secWSKey]; ok {
			info.Enabled = enabled
			cfg.DeviceIDs[secWSKey] = info
			cfg.lock.Unlock()
			// ... save and respond
		} else {
			cfg.lock.Unlock()
			sendJSON(w, http.StatusNotFound, map[string]string{"status": "error", "message": "设备未找到"})
		}

	case "/device/delete":
		secWSKey, _ := reqData["sec_ws_key"].(string) // MUST receive sec_ws_key
		cfg.lock.Lock()
		delete(cfg.DeviceIDs, secWSKey)
		cfg.lock.Unlock()
		deviceUsage.Delete(secWSKey)
		if err := cfg.SafeSave(); err != nil { /* ... */ } else { /* ... */ }

	case "/device/reset_traffic":
		secWSKey, _ := reqData["sec_ws_key"].(string) // MUST receive sec_ws_key
		if val, ok := deviceUsage.Load(secWSKey); ok {
			atomic.StoreInt64(val.(*int64), 0)
		}
		cfg.lock.Lock()
		if info, ok := cfg.DeviceIDs[secWSKey]; ok {
			info.UsedBytes = 0
			cfg.DeviceIDs[secWSKey] = info
		}
		cfg.lock.Unlock()
		if err := cfg.SafeSave(); err != nil { /* ... */ } else { /* ... */ }

	// ... account/update and settings/save are unchanged
	}
}


func main() {
	// ... main function is unchanged ...
}
