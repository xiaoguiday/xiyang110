#!/bin/bash
set -e

# 默认端口
WSS_PORT=80
STUNNEL_PORT=443
UDPGW_PORT=7300

# 读取自定义端口
read -p "请输入 WSS 端口（默认 80）: " input
WSS_PORT=${input:-80}

read -p "请输入 Stunnel4 端口（默认 443）: " input
STUNNEL_PORT=${input:-443}

read -p "请输入 UDPGW 端口（默认 7300）: " input
UDPGW_PORT=${input:-7300}

# 更新系统并安装依赖
echo "==== 更新系统并安装依赖 ===="
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools stunnel4 openssl
echo "依赖安装完成"

# -------------------------------
# 安装 WSS 脚本
# -------------------------------
echo "==== 安装 WSS 脚本 ===="
WSS_FILE="/usr/local/bin/wss"
sudo tee $WSS_FILE > /dev/null <<'EOF'
#!/usr/bin/python3
import socket, threading, select, sys, time

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
BUFLEN = 4096*4
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
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
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
            print(log)

    def addConn(self, conn):
        with self.threadsLock:
            if self.running:
                self.threads.append(conn)

    def removeConn(self, conn):
        with self.threadsLock:
            self.threads.remove(conn)

    def close(self):
        with self.threadsLock:
            for c in list(self.threads):
                c.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = b''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        if not self.clientClosed:
            try:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
            except: pass
            self.clientClosed = True
        if not self.targetClosed:
            try:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
            except: pass
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host') or DEFAULT_HOST
            passwd = self.findHeader(self.client_buffer, 'X-Pass')
            self.method_CONNECT(hostPort)
        except Exception as e:
            self.log += ' - error: ' + str(e)
            self.server.printLog(self.log)
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        if isinstance(head, bytes):
            head = head.decode('utf-8', errors='ignore')
        aux = head.find(header + ': ')
        if aux == -1: return ''
        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')
        return head[:aux] if aux != -1 else ''

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            port = 22
        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]
        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.server.printLog('CONNECT ' + path)
        self.connect_target(path)
        self.client.sendall(RESPONSE.encode('utf-8'))
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            recv, _, err = select.select(socs, [], socs, 3)
            if err: error = True
            for in_ in recv:
                try:
                    data = in_.recv(BUFLEN)
                    if data:
                        if in_ is self.target:
                            self.client.send(data)
                        else:
                            while data:
                                byte = self.target.send(data)
                                data = data[byte:]
                        count = 0
                    else:
                        break
                except:
                    error = True
            if count == TIMEOUT or error: break

def main():
    server = Server('0.0.0.0', LISTENING_PORT)
    server.start()
    while True:
        time.sleep(2)

if __name__ == '__main__':
    main()
EOF

sudo chmod +x $WSS_FILE
echo "WSS 脚本安装完成: $WSS_FILE"

# -------------------------------
# 创建 WSS systemd 服务
# -------------------------------
echo "==== 创建 WSS systemd 服务 ===="
sudo tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $WSS_FILE $WSS_PORT
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wss
sudo systemctl start wss
echo "WSS systemd 服务已启动"

# -------------------------------
# 安装 Stunnel4 并生成证书
# -------------------------------
echo "==== 安装 Stunnel4 并生成证书 ===="
sudo mkdir -p /etc/stunnel/certs
CERT_FILE="/etc/stunnel/certs/stunnel.pem"

sudo openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com"

sudo cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > $CERT_FILE
sudo chmod 644 /etc/stunnel/certs/*.key /etc/stunnel/certs/*.crt /etc/stunnel/certs/*.pem
echo "Stunnel4 证书生成完成"

# 创建 Stunnel4 配置
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
accept = 0.0.0.0:$STUNNEL_PORT
cert = $CERT_FILE
key = $CERT_FILE
connect = 127.0.0.1:22
EOF

sudo systemctl enable stunnel4
sudo systemctl restart stunnel4
echo "Stunnel4 安装并启动完成，端口: $STUNNEL_PORT"

# -------------------------------
# 安装 UDPGW
# -------------------------------
echo "==== 安装 UDPGW ===="
bash <(curl -Ls https://raw.githubusercontent.com/xpanel-cp/XPanel-SSH-User-Management/master/fix-call.sh --ipv4)
echo "UDPGW 安装完成，默认端口: $UDPGW_PORT"

# 创建 UDPGW systemd 服务
sudo tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
[Unit]
Description=UDPGW Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/udpgw --listen-addr 0.0.0.0:$UDPGW_PORT
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable udpgw
sudo systemctl start udpgw
echo "UDPGW systemd 服务已启动，端口: $UDPGW_PORT"

# -------------------------------
# 完成提示
# -------------------------------
echo "==== 安装完成 ===="
echo "WSS 端口: $WSS_PORT"
echo "Stunnel4 端口: $STUNNEL_PORT"
echo "UDPGW 端口: $UDPGW_PORT"
echo "可使用以下命令查看日志:"
echo "  sudo journalctl -u wss -f"
echo "  sudo journalctl -u stunnel4 -f"
echo "  sudo journalctl -u udpgw -f"
