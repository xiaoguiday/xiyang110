#!/bin/bash

# 默认端口
payload_PORT=80
UDPGW_PORT=7300
STUNNEL_PORT=443

# 等待 apt 可用
wait_for_apt() {
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        echo "等待其他 apt 进程完成..."
        sleep 2
    done
}

# 安装系统依赖
install_packages() {
    wait_for_apt
    echo "==== 更新系统 ===="
    sudo apt update -y
    echo "==== 安装 Python3、pip、wget、curl、git、net-tools ===="
    sudo apt install -y python3 python3-pip wget curl git net-tools
    echo "依赖安装完成"
}

# 创建 WSS Python 脚本
install_wss() {
    echo "==== 安装 WSS Python 脚本 ===="
    mkdir -p ~/wss
    cat > ~/wss/wss.py <<'EOF'
#!/usr/bin/python3
import socket, threading, select, sys, time

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1])
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:22'
RESPONSE = 'HTTP/1.1 101 Switching Protocols\r\nContent-Length: 104857600000\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = True
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()

    def run(self):
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        soc.bind((self.host, self.port))
        soc.listen(0)
        print(f"WSS 监听 {self.host}:{self.port}")
        try:
            while self.running:
                c, addr = soc.accept()
                c.setblocking(1)
                conn = ConnectionHandler(c)
                conn.start()
                self.addConn(conn)
        finally:
            soc.close()

    def addConn(self, conn):
        with self.threadsLock:
            self.threads.append(conn)

class ConnectionHandler(threading.Thread):
    def __init__(self, client):
        threading.Thread.__init__(self)
        self.client = client
        self.target = None
        self.targetClosed = True
        self.clientClosed = False

    def run(self):
        try:
            client_buffer = self.client.recv(BUFLEN)
            hostPort = DEFAULT_HOST
            if hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                self.connect_target(hostPort)
                self.client.sendall(RESPONSE.encode())
                self.doCONNECT()
        finally:
            self.close()

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            port = 22
        self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target.connect((host, port))
        self.targetClosed = False

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            recv, _, err = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for s in recv:
                    try:
                        data = s.recv(BUFLEN)
                        if data:
                            if s is self.target:
                                self.client.sendall(data)
                            else:
                                self.target.sendall(data)
                            count = 0
                        else:
                            break
                    except:
                        error = True
                        break
            if count == TIMEOUT or error:
                break

    def close(self):
        if not self.clientClosed:
            try: self.client.shutdown(socket.SHUT_RDWR); self.client.close()
            except: pass
            self.clientClosed = True
        if self.target and not self.targetClosed:
            try: self.target.shutdown(socket.SHUT_RDWR); self.target.close()
            except: pass
            self.targetClosed = True

if __name__ == '__main__':
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True: time.sleep(2)
EOF

    chmod +x ~/wss/wss.py
    echo "WSS 脚本安装完成，默认端口 $WSS_PORT"
}

# 安装 UDPGW
install_udpgw() {
    echo "==== 安装 UDPGW ===="
    bash <(curl -Ls https://raw.githubusercontent.com/xpanel-cp/XPanel-SSH-User-Management/master/fix-call.sh --ipv4) $UDPGW_PORT
    echo "UDPGW 安装完成，端口 $UDPGW_PORT"
}

# 安装 stunnel4 并生成证书
install_stunnel() {
    echo "==== 安装 stunnel4 ===="
    sudo apt install -y stunnel4 openssl

    CERT_DIR="/etc/stunnel/certs"
    sudo mkdir -p $CERT_DIR
    CERT_KEY="$CERT_DIR/stunnel.key"
    CERT_CRT="$CERT_DIR/stunnel.crt"
    CERT_PEM="$CERT_DIR/stunnel.pem"

    echo "生成自签名证书..."
    sudo openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$CERT_KEY" \
        -out "$CERT_CRT" \
        -days 1095 \
        -subj "/CN=wss.example.com"

    sudo sh -c "cat $CERT_KEY $CERT_CRT > $CERT_PEM"
    sudo chmod 644 $CERT_KEY $CERT_CRT $CERT_PEM

    echo "生成 stunnel 配置..."
    sudo tee /etc/stunnel/wss.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[wss]
accept = 0.0.0.0:$STUNNEL_PORT
cert = $CERT_PEM
key = $CERT_PEM
connect = 127.0.0.1:$WSS_PORT
EOF

    sudo systemctl enable stunnel4
    sudo systemctl restart stunnel4
    echo "stunnel4 安装完成，端口 $STUNNEL_PORT"
}

# 询问用户端口
read -p "请输入 WSS 端口（默认 80）: " input
[ ! -z "$input" ] && WSS_PORT=$input
read -p "请输入 UDPGW 端口（默认 7300）: " input
[ ! -z "$input" ] && UDPGW_PORT=$input
read -p "请输入 stunnel4 端口（默认 443）: " input
[ ! -z "$input" ] && STUNNEL_PORT=$input

# 执行安装
install_packages
install_wss
install_udpgw
install_stunnel

echo "==== 安装完成 ===="
echo "WSS 端口: $WSS_PORT"
echo "UDPGW 端口: $UDPGW_PORT"
echo "stunnel4 端口: $STUNNEL_PORT"
echo "WSS 脚本路径: ~/wss/wss.py"
