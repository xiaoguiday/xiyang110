#!/bin/bash

# =============================
# 功能函数：检查端口是否被占用
# =============================
check_port() {
    local port=$1
    local service_name=$2
    echo "正在检查端口 $port 是否被 $service_name 使用..."
    if ss -tlpn | grep -q ":$port\b"; then
        echo "❌ 错误：端口 $port 已被占用！请停止占用该端口的程序后重试。"
        echo "   你可以使用 'sudo ss -tlpn | grep :$port' 命令查看是哪个程序占用了端口。"
        exit 1
    else
        echo "✅ 端口 $port 可用。"
    fi
}

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
# 安装 ss 工具用于端口检查
sudo apt-get install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 iproute2
echo "依赖安装完成"
echo "----------------------------------"

# =============================
# 安装 WSS 脚本
# =============================
echo "==== 准备安装 WSS 脚本 ===="
check_port $WSS_PORT "WSS"

sudo tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
import socket, threading, select, sys, time

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
PASS = ''
BUFLEN = 8192
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:550'
RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        try:
            self.soc.bind((self.host, int(self.port)))
        except Exception as e:
            print(f"Error binding to {self.host}:{self.port} - {e}")
            return
        self.soc.listen(0)
        self.running = True
        while self.running:
            try:
                c, addr = self.soc.accept()
                c.setblocking(True)
                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
            except socket.timeout:
                continue
            except Exception:
                break
        self.close()
    def addConn(self, conn):
        with self.threadsLock:
            if self.running: self.threads.append(conn)
    def removeConn(self, conn):
        with self.threadsLock:
            if conn in self.threads: self.threads.remove(conn)
    def close(self):
        self.running = False
        with self.threadsLock:
            threads = list(self.threads)
            for c in threads: c.close()
        self.soc.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.client = socClient
        self.server = server
        self.log = f'Connection: {addr}'
        self.target = None
    def close(self):
        if self.client:
            try: self.client.shutdown(socket.SHUT_RDWR)
            except: pass
            self.client.close()
        if self.target:
            try: self.target.shutdown(socket.SHUT_RDWR)
            except: pass
            self.target.close()
        self.server.removeConn(self)
    def run(self):
        try:
            client_buffer = self.client.recv(BUFLEN)
            hostPort = self.findHeader(client_buffer, 'X-Real-Host') or DEFAULT_HOST
            self.connect_target(hostPort)
            self.client.sendall(RESPONSE)
            self.do_proxy()
        except Exception as e:
            self.log += f' - error: {e}'
            print(self.log)
        finally:
            self.close()
    def findHeader(self, head, header):
        try:
            head_str = head.decode('utf-8', 'ignore')
            aux = head_str.find(f'{header}: ')
            if aux == -1: return ''
            start = aux + len(header) + 2
            end = head_str.find('\r\n', start)
            return head_str[start:end] if end != -1 else ''
        except: return ''
    def connect_target(self, host):
        host, port = (host.split(':') + ['22'])[:2]
        self.target = socket.create_connection((host, int(port)))
        print(f'{self.log} - CONNECT {host}:{port}')
    def do_proxy(self):
        sockets = [self.client, self.target]
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, TIMEOUT)
            if exceptional: break
            if not readable: break
            for sock in readable:
                data = sock.recv(BUFLEN)
                if not data: return
                if sock is self.client:
                    self.target.sendall(data)
                else:
                    self.client.sendall(data)

def main():
    print(":-------PythonProxy WSS-------:")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    print(f"Listening addr: {LISTENING_ADDR}, port: {LISTENING_PORT}")
    try:
        server.join()
    except KeyboardInterrupt:
        print('Stopping...')
        server.close()

if __name__ == '__main__':
    main()
EOF

sudo chmod +x /usr/local/bin/wss
echo "WSS 脚本写入完成。"

sudo tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/wss $WSS_PORT
Restart=on-failure
User=root
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

echo "启动并验证 WSS 服务..."
sudo systemctl daemon-reload
sudo systemctl enable wss > /dev/null 2>&1
sudo systemctl restart wss
sleep 2 # 等待服务启动
if systemctl is-active --quiet wss; then
    echo "✅ WSS 服务 (端口 $WSS_PORT) 成功启动。"
else
    echo "❌ WSS 服务启动失败！请检查日志："
    sudo journalctl -u wss -n 20 --no-pager
    exit 1
fi
echo "----------------------------------"

# =============================
# 安装 Stunnel4
# =============================
echo "==== 准备安装 Stunnel4 ===="
check_port $STUNNEL_PORT "Stunnel4"

sudo mkdir -p /etc/stunnel/certs
sudo openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.pem \
-out /etc/stunnel/certs/stunnel.pem \
-days 3650 \
-subj "/CN=localhost"
sudo chmod 600 /etc/stunnel/certs/stunnel.pem

sudo tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid = /var/run/stunnel4/stunnel.pid
client = no
[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
cert = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:550
EOF

sudo tee /etc/default/stunnel4 > /dev/null <<'EOF'
ENABLED=1
FILES="/etc/stunnel/ssh-tls.conf"
OPTIONS=""
PPP_RESTART=0
EOF

sudo mkdir -p /var/run/stunnel4
sudo chown -R stunnel4:stunnel4 /var/run/stunnel4/

echo "启动并验证 Stunnel4 服务..."
sudo systemctl restart stunnel4
sleep 2 # 等待服务启动
if systemctl is-active --quiet stunnel4; then
    echo "✅ Stunnel4 服务 (端口 $STUNNEL_PORT) 成功启动。"
else
    echo "❌ Stunnel4 服务启动失败！请检查日志："
    sudo journalctl -u stunnel4 -n 20 --no-pager
    exit 1
fi
echo "----------------------------------"

# =============================
# 安装 UDPGW
# =============================
echo "==== 准备安装 UDPGW ===="
if [ -d "/root/badvpn" ]; then
    echo "badvpn 目录已存在，跳过克隆。"
else
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn
fi
mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
echo "正在编译 badvpn-udpgw..."
make -j$(nproc)

# --- [核心诊断] ---
UDPGW_EXEC="/root/badvpn/badvpn-build/udpgw/badvpn-udpgw"
if [ ! -f "$UDPGW_EXEC" ]; then
    echo "❌ 错误：badvpn-udpgw 编译失败，可执行文件 '$UDPGW_EXEC' 未找到！"
    echo "   请检查上面的编译输出日志是否有错误。"
    exit 1
fi
echo "✅ badvpn-udpgw 编译成功。"

sudo tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
Type=simple
ExecStart=$UDPGW_EXEC --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1024
Restart=on-failure
User=root
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

echo "启动并验证 UDPGW 服务..."
sudo systemctl daemon-reload
sudo systemctl enable udpgw > /dev/null 2>&1
sudo systemctl restart udpgw
sleep 2 # 等待服务启动
if systemctl is-active --quiet udpgw; then
    echo "✅ UDPGW 服务 (端口 $UDPGW_PORT) 成功启动。"
else
    echo "❌ UDPGW 服务启动失败！请检查日志："
    sudo journalctl -u udpgw -n 20 --no-pager
    exit 1
fi
echo "----------------------------------"

# =============================
# 最终状态报告
# =============================
echo ""
echo "================================================="
echo "🎉 脚本执行成功！所有服务均已正常启动。"
echo "-------------------------------------------------"
echo "✅ WSS 服务       (端口 $WSS_PORT) - 状态: 正在运行 (active)"
echo "✅ Stunnel4 服务   (端口 $STUNNEL_PORT) - 状态: 正在运行 (active)"
echo "✅ UDPGW 服务      (端口 $UDPGW_PORT) - 状态: 正在运行 (active)"
echo "================================================="
