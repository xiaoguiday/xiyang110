#!/usr/bin/env bash

set -e

# =============================
#  用户自定义端口
# =============================
read -p "请输入 WSS 监听端口（默认80）: " WSS_PORT
WSS_PORT=${WSS_PORT:-80}

read -p "请输入 TUNNEL4 端口（默认443）: " TUNNEL4_PORT
TUNNEL4_PORT=${TUNNEL4_PORT:-443}

echo "WSS端口: $WSS_PORT"
echo "TUNNEL4端口: $TUNNEL4_PORT"
echo "----------------------------------"

# =============================
#  系统更新和依赖安装
# =============================
echo "==== 更新系统 & 安装依赖 ===="
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools stunnel4 build-essential cmake
echo "依赖安装完成."
echo "----------------------------------"

# =============================
#  创建 WSS 脚本
# =============================
echo "==== 创建 WSS 脚本 ===="
WSS_FILE="/usr/local/bin/wss"
cat <<EOF | sudo tee $WSS_FILE > /dev/null
#!/usr/bin/env python3
import socket, threading, select, sys, time

LISTEN_ADDR = '0.0.0.0'
LISTEN_PORT = $WSS_PORT
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:22'
RESPONSE = 'HTTP/1.1 101 Switching Protocols\\r\\nContent-Length: 104857600000\\r\\n\\r\\n'

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
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True
        try:
            while self.running:
                c, addr = self.soc.accept()
                c.setblocking(1)
                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print(log)
        self.logLock.release()

    def addConn(self, conn):
        self.threadsLock.acquire()
        self.threads.append(conn)
        self.threadsLock.release()

    def removeConn(self, conn):
        self.threadsLock.acquire()
        if conn in self.threads:
            self.threads.remove(conn)
        self.threadsLock.release()

    def close(self):
        self.threadsLock.acquire()
        for c in list(self.threads):
            c.client.close()
            c.target.close()
        self.threadsLock.release()

class ConnectionHandler(threading.Thread):
    def __init__(self, client, server, addr):
        threading.Thread.__init__(self)
        self.client = client
        self.target = None
        self.server = server
        self.log = f"Connection: {addr}"

    def run(self):
        try:
            data = self.client.recv(BUFLEN)
            hostPort = DEFAULT_HOST
            self.connect_target(hostPort)
            self.client.sendall(RESPONSE.encode('utf-8'))
            self.do_connect()
        except Exception as e:
            self.server.printLog(f"{self.log} - error: {e}")
        finally:
            self.client.close()
            if self.target:
                self.target.close()
            self.server.removeConn(self)

    def connect_target(self, host):
        host_split = host.split(":")
        h = host_split[0]
        p = int(host_split[1])
        self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target.connect((h, p))

    def do_connect(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            recv, _, err = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
                    try:
                        data = in_.recv(BUFLEN)
                        if data:
                            if in_ is self.target:
                                self.client.send(data)
                            else:
                                while data:
                                    sent = self.target.send(data)
                                    data = data[sent:]
                            count = 0
                        else:
                            break
                    except:
                        error = True
                        break
            if count >= TIMEOUT or error:
                break

if __name__ == "__main__":
    server = Server(LISTEN_ADDR, LISTEN_PORT)
    server.start()
    while True:
        time.sleep(2)
EOF

sudo chmod +x $WSS_FILE
echo "WSS 脚本创建完成: $WSS_FILE"
echo "----------------------------------"

# =============================
#  创建 systemd 服务自动启动 WSS
# =============================
echo "==== 创建 systemd 服务 (wss.service) ===="
cat <<EOF | sudo tee /etc/systemd/system/wss.service > /dev/null
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=$WSS_FILE $WSS_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wss
sudo systemctl start wss
echo "WSS 服务已启动并设置开机自启."
echo "----------------------------------"

# =============================
#  安装 Stunnel4 并自动生成证书
# =============================
echo "==== 安装 Stunnel4 ===="
sudo apt install -y stunnel4
echo "生成本地证书..."
sudo mkdir -p /etc/stunnel/certs
CERT_KEY="/etc/stunnel/certs/ssh.key"
CERT_CRT="/etc/stunnel/certs/ssh.crt"
CERT_PEM="/etc/stunnel/certs/ssh.pem"
sudo openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout $CERT_KEY \
    -out $CERT_CRT \
    -days 1095 \
    -subj "/CN=example.com"
sudo sh -c "cat $CERT_KEY $CERT_CRT > $CERT_PEM"
sudo chmod 644 /etc/stunnel/certs/*.pem
sudo chmod 644 /etc/stunnel/certs/*.crt
echo "证书生成完成."

echo "创建 Stunnel4 配置..."
STUNNEL_CONF="/etc/stunnel/ssh-tls.conf"
sudo tee $STUNNEL_CONF > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$TUNNEL4_PORT
cert = $CERT_PEM
key = $CERT_PEM
connect = 127.0.0.1:22
EOF

sudo systemctl enable stunnel4
sudo systemctl restart stunnel4
echo "Stunnel4 已安装并启动，监听端口: $TUNNEL4_PORT"
echo "----------------------------------"

# =============================
#  安装 TUNNEL4 (HTTP payload)
# =============================
echo "==== 安装 TUNNEL4 ===="
bash <(curl -Ls https://raw.githubusercontent.com/xiaoguiday/http-payload/refs/heads/main/http-payload.sh) $TUNNEL4_PORT
echo "TUNNEL4 安装完成."
echo "----------------------------------"

# =============================
#  安装完成总结
# =============================
echo "==== 安装完成 ===="
echo "WSS 脚本: $WSS_FILE 端口: $WSS_PORT"
echo "Stunnel4 TLS 端口: $TUNNEL4_PORT"
echo "TUNNEL4 HTTP payload 端口: $TUNNEL4_PORT"
echo "----------------------------------"
echo "检查服务状态: "
echo "sudo systemctl status wss"
echo "sudo systemctl status stunnel4"
