#!/bin/bash
set -e
set -u
set -o pipefail

# 默认端口
payload_PORT=80
UDPGW_PORT=7300
STUNNEL_PORT=443

# 读取用户自定义端口
read -p "请输入 WSS 监听端口（默认 80）: " input
[ -n "$input" ] && WSS_PORT=$input

read -p "请输入 UDPGW 端口（默认 7300）: " input
[ -n "$input" ] && UDPGW_PORT=$input

read -p "请输入 stunnel4 监听端口（默认 443）: " input
[ -n "$input" ] && STUNNEL_PORT=$input

echo "============================="
echo "WSS端口: $WSS_PORT"
echo "UDPGW端口: $UDPGW_PORT"
echo "stunnel端口: $STUNNEL_PORT"
echo "============================="

# 等待 apt 可用
wait_for_apt() {
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 ; do
        echo "等待其他 apt 进程完成..."
        sleep 2
    done
}

# 安装依赖
install_packages() {
    wait_for_apt
    echo "更新系统源..."
    sudo apt update -y
    echo "安装 Python3、pip、wget、curl、git、net-tools 等依赖..."
    sudo apt install -y python3 python3-pip wget curl git net-tools unzip
    echo "依赖安装完成"
}

# 创建 WSS 脚本
create_wss() {
    echo "==== 创建 WSS 脚本 ===="
    WSS_PATH="/usr/local/bin/wss.py"
    sudo tee $WSS_PATH > /dev/null <<'EOF'
#!/usr/bin/python3
import socket, threading, select, sys, time

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:22'
RESPONSE = 'HTTP/1.1 101 Switching Protocols\r\nContent-Length: 104857600000\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.lock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True
        print(f"WSS监听 {self.host}:{self.port}")
        try:
            while self.running:
                c, addr = self.soc.accept()
                c.setblocking(1)
                conn = ConnectionHandler(c, self)
                conn.start()
                with self.lock:
                    self.threads.append(conn)
        finally:
            self.running = False
            self.soc.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, client, server):
        threading.Thread.__init__(self)
        self.client = client
        self.server = server
        self.target = None

    def run(self):
        try:
            data = self.client.recv(BUFLEN)
            self.target = socket.create_connection(('127.0.0.1', 22))
            self.client.sendall(RESPONSE.encode())
            sockets = [self.client, self.target]
            while True:
                r, _, _ = select.select(sockets, [], [], 3)
                if not r:
                    break
                for s in r:
                    other = self.target if s is self.client else self.client
                    try:
                        buf = s.recv(BUFLEN)
                        if buf:
                            other.sendall(buf)
                        else:
                            return
                    except:
                        return
        finally:
            self.client.close()
            if self.target:
                self.target.close()

if __name__ == '__main__':
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        time.sleep(2)
EOF

    sudo chmod +x $WSS_PATH
    echo "WSS 脚本创建完成: $WSS_PATH"
}

# 安装 UDPGW
install_udpgw() {
    echo "==== 安装 UDPGW ===="
    bash <(curl -Ls https://raw.githubusercontent.com/xpanel-cp/XPanel-SSH-User-Management/master/fix-call.sh) $UDPGW_PORT
    echo "UDPGW 安装完成"
}

# 安装 stunnel4
install_stunnel() {
    echo "==== 安装 stunnel4 ===="
    sudo apt install -y stunnel4 openssl
    echo "生成自签证书..."
    sudo mkdir -p /etc/stunnel/certs
    sudo openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout /etc/stunnel/certs/self.key \
      -out /etc/stunnel/certs/self.crt \
      -days 1095 \
      -subj "/CN=self-signed"
    sudo sh -c 'cat /etc/stunnel/certs/self.key /etc/stunnel/certs/self.crt > /etc/stunnel/certs/self.pem'
    sudo chmod 644 /etc/stunnel/certs/*.pem
    sudo chmod 644 /etc/stunnel/certs/*.crt

    echo "创建 stunnel 配置..."
    sudo tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root

client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
cert = /etc/stunnel/certs/self.pem
key = /etc/stunnel/certs/self.pem
connect = 127.0.0.1:22
EOF

    echo "启用并启动 stunnel"
    sudo systemctl enable stunnel4
    sudo systemctl restart stunnel4
    echo "stunnel4 安装完成"
}

main() {
    install_packages
    create_wss
    install_udpgw
    install_stunnel
    echo "全部安装完成"
}

main
