package main

import (
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
	"golang.org/x/crypto/bcrypt"
)

// 你的原 RingBuffer 日志、Config、Settings 等结构体保持原样

type DeviceInfo struct {
	Expiry      string `json:"expiry"`
	LimitGB     int    `json:"limit_gb"`
	UsedBytes   int64  `json:"used_bytes"`
	SecWSKey    string `json:"sec_ws_key"`   // 新增
	MaxSessions int    `json:"max_sessions"` // 新增
}

// ...其它结构体和原代码保持不变...

func (c *Config) GetDeviceIDs() map[string]DeviceInfo {
	c.lock.RLock()
	defer c.lock.RUnlock()
	devices := make(map[string]DeviceInfo)
	for k, v := range c.DeviceIDs {
		// 自动补全新字段
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

// ========== 密码哈希相关 ==========
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ========== 账号修改API ==========
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
	// ...其它API保持你的原样...
	}
}

// ========== 设备列表API自动支持新字段（结构体自动兼容） ==========

// ...其它代码保持你的原样...

func main() {
	// ...你的原 main 保持不变...
}
