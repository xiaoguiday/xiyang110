#!/bin/bash
# 移除了 set -e，脚本不会因单个命令错误而中止

# =============================
# 提示端口
# =============================
read -p "请输入 WSS 监听端口（默认80）: " WSS_PORT
WSS_PORT=${WSS_PORT:-80}

read -p "请输入 Stunnel4 端口（默认443）: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-443}

read -p "请输入 UDPGW 端口（默认7300）: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

# =============================
# 系统更新与依赖安装
# =============================
echo "==== 更新系统并安装依赖 ===="
sudo apt-get update -y
sudo apt-get install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4
echo "依赖安装完成"
echo "----------------------------------"

# =============================
# 安装 WSS 脚本
# =============================
echo "==== 安装 WSS 脚本 ===="
sudo tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
import socket, threading, select, sys, time

LISTENING_ADDR = '0.0.0.0'
# Use sys.argv to get port from command line
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
PASS = ''
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:22'
RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nContent-Length: 104857600000\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()
    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, int(self.port)))
        self.soc.listen(0)
        self.running = True
        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()
    def printLog(self, log):
        with self.logLock:
            print(log, flush=True)
    def addConn(self, conn):
        with self.threadsLock:
            if self.running:
                self.threads.append(conn)
    def removeConn(self, conn):
        with self.threadsLock:
            try:
                self.threads.remove(conn)
            except ValueError:
                pass
    def close(self):
        self.running = False
        with self.threadsLock:
            threads = list(self.threads)
            for c in threads:
                c.close()
        self.soc.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.server = server
        self.log = f'Connection: {addr}'
    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True
        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True
    def run(self):
        try:
            client_buffer = self.client.recv(BUFLEN)
            hostPort = self.findHeader(client_buffer, 'X-Real-Host') or DEFAULT_HOST
            passwd = self.findHeader(client_buffer, 'X-Pass')
            if PASS and passwd != PASS:
                self.client.send(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                return
            self.method_CONNECT(hostPort)
        except Exception as e:
            self.log += f' - error: {e}'
            self.server.printLog(self.log)
        finally:
            self.close()
            self.server.removeConn(self)
    def findHeader(self, head, header):
        try:
            head_str = head.decode('utf-8', errors='ignore')
            aux = head_str.find(f'{header}: ')
            if aux == -1: return ''
            start = aux + len(header) + 2
            end = head_str.find('\r\n', start)
            if end == -1: return ''
            return head_str[start:end]
        except:
            return ''
    def connect_target(self, host):
        host, port_str = (host.split(':') + ['22'])[:2]
        port = int(port_str)
        soc_family, _, _, _, address = socket.getaddrinfo(host, port)[0]
        self.target = socket.socket(soc_family)
        self.targetClosed = False
        self.target.connect(address)
    def method_CONNECT(self, path):
        self.log += f' - CONNECT {path}'
        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.server.printLog(self.log)
        self.doCONNECT()
    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while not error:
            count += 1
            try:
                readable, _, exceptional = select.select(socs, [], socs, 3)
                if exceptional:
                    error = True
                    break
                for sock in readable:
                    data = sock.recv(BUFLEN)
                    if not data:
                        error = True
                        break
                    if sock is self.client:
                        self.target.sendall(data)
                    else:
                        self.client.sendall(data)
                    count = 0
                if count >= TIMEOUT:
                    error = True
            except:
                error = True

def main():
    print("\n:-------PythonProxy WSS-------:\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    print(f"Listening addr: {LISTENING_ADDR}, port: {LISTENING_PORT}\n")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print('Stopping...')
        server.close()

if __name__ == '__main__':
    main()
EOF

sudo chmod +x /usr/local/bin/wss
echo "WSS 脚本安装完成"
echo "----------------------------------"

# 创建 systemd 服务
# --- [核心修复] ---
# 使用 <<'EOF' 防止变量$WSS_PORT在创建文件时被bash解析
sudo tee /etc/systemd/system/wss.service > /dev/null <<'EOF'
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
# 注意：这里的端口变量 $WSS_PORT 是 bash 变量，它将在创建文件时被替换
# 如果希望由 systemd 动态处理，需要使用 EnvironmentFile 或其他方式
ExecStart=/usr/bin/python3 /usr/local/bin/wss ${WSS_PORT}
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

# 由于上面的EOF是带引号的，bash不会替换${WSS_PORT}，所以我们需要手动替换
sudo sed -i "s|\${WSS_PORT}|$WSS_PORT|g" /etc/systemd/system/wss.service

sudo systemctl daemon-reload
sudo systemctl enable wss
sudo systemctl start wss
echo "WSS 已启动，端口 $WSS_PORT"
echo "----------------------------------"

# =============================
# 安装 Stunnel4 并生成证书
# =============================
echo "==== 安装 Stunnel4 ===="
sudo mkdir -p /etc/stunnel/certs
sudo openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 3650 \
-subj "/C=US/ST=CA/L=SF/O=MyOrg/OU=IT/CN=localhost"

sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
sudo chmod 640 /etc/stunnel/certs/stunnel.key
sudo chmod 644 /etc/stunnel/certs/stunnel.crt
sudo chmod 640 /etc/stunnel/certs/stunnel.pem

# --- [核心修复] ---
# 使用 <<'EOF' 防止变量$STUNNEL_PORT在创建文件时被bash解析
sudo tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid = /var/run/stunnel4/stunnel.pid
setuid = root
setgid = root
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[ssh-tls-gateway]
accept = 0.0.0.0:${STUNNEL_PORT}
cert = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:22
EOF

# 手动替换 Stunnel 端口变量
sudo sed -i "s|\${STUNNEL_PORT}|$STUNNEL_PORT|g" /etc/stunnel/ssh-tls.conf

sudo tee /etc/default/stunnel4 > /dev/null <<'EOF'
ENABLED=1
FILES="/etc/stunnel/ssh-tls.conf"
OPTIONS=""
PPP_RESTART=0
EOF

sudo mkdir -p /var/run/stunnel4
# stunnel4 在 Debian/Ubuntu 上的默认用户是 stunnel4
sudo chown -R stunnel4:stunnel4 /var/run/stunnel4/
sudo chown -R stunnel4:stunnel4 /etc/stunnel/

echo "尝试启用并重启 Stunnel4..."
sudo systemctl restart stunnel4
sudo systemctl enable stunnel4 > /dev/null 2>&1

echo "Stunnel4 安装完成，端口 $STUNNEL_PORT"
echo "----------------------------------"

# =============================
# 安装 UDPGW
# =============================
echo "==== 安装 UDPGW ===="
if [ -d "/root/badvpn" ]; then
    echo "/root/badvpn 已存在，跳过克隆"
else
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn
fi
mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc)

# 创建 systemd 服务
# --- [核心修复] ---
# 使用 <<'EOF' 防止变量$UDPGW_PORT在创建文件时被bash解析
sudo tee /etc/systemd/system/udpgw.service > /dev/null <<'EOF'
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
Type=simple
ExecStart=/root/badvpn/badvpn-build/udpgw/badvpn-udpgw --listen-addr 127.0.0.1:${UDPGW_PORT} --max-clients 1024 --max-connections-for-client 10
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

# 手动替换 UDPGW 端口变量
sudo sed -i "s|\${UDPGW_PORT}|$UDPGW_PORT|g" /etc/systemd/system/udpgw.service

sudo systemctl daemon-reload
sudo systemctl enable udpgw
sudo systemctl start udpgw
echo "UDPGW 已安装并启动，端口: $UDPGW_PORT"
echo "----------------------------------"

# =============================
# 最终状态报告
# =============================
echo ""
echo "================================================="
echo "🎉 脚本执行完毕！"
echo ""
echo "请务必检查以下服务的状态，确保它们都正常运行："
echo "-------------------------------------------------"

# 检查 WSS 服务
if systemctl is-active --quiet wss; then
    echo "✅ WSS 服务 (端口 $WSS_PORT) - 状态: 正在运行 (active)"
else
    echo "❌ WSS 服务 (端口 $WSS_PORT) - 状态: 启动失败 (inactive/failed)"
    echo "   -> 请运行 'sudo journalctl -u wss -n 50 --no-pager' 查看日志"
fi

# 检查 Stunnel4 服务
if systemctl is-active --quiet stunnel4; then
    echo "✅ Stunnel4 服务 (端口 $STUNNEL_PORT) - 状态: 正在运行 (active)"
else
    echo "❌ Stunnel4 服务 (端口 $STUNNEL_PORT) - 状态: 启动失败 (inactive/failed)"
    echo "   -> 请运行 'sudo journalctl -u stunnel4 -n 50 --no-pager' 查看日志"
fi

# 检查 UDPGW 服务
if systemctl is-active --quiet udpgw; then
    echo "✅ UDPGW 服务 (端口 $UDPGW_PORT) - 状态: 正在运行 (active)"
else
    echo "❌ UDPGW 服务 (端口 $UDPGW_PORT) - 状态: 启动失败 (inactive/failed)"
    echo "   -> 请运行 'sudo journalctl -u udpgw -n 50 --no-pager' 查看日志"
fi
echo "-------------------------------------------------"
echo "如果发现有失败的服务，请使用上面提示的 'journalctl' 命令查看详细错误日志。"
echo "================================================="
