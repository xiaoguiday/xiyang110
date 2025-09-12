#!/bin/bash
set -e

# 默认端口
WSS_PORT=80
STUNNEL_PORT=443
UDPGW_PORT=7300

# 提示用户自定义端口
read -p "请输入 WSS 监听端口（默认80）:" input
[ -n "$input" ] && WSS_PORT=$input

read -p "请输入 stunnel4 监听端口（默认443）:" input
[ -n "$input" ] && STUNNEL_PORT=$input

read -p "请输入 UDPGW 监听端口（默认7300）:" input
[ -n "$input" ] && UDPGW_PORT=$input

# ====== 系统更新和依赖安装 ======
echo "==== 更新系统并安装依赖 ===="
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools stunnel4

# ====== 创建 WSS 脚本 ======
echo "==== 创建 WSS 脚本 ===="
WSS_PATH="/usr/local/bin/wss"
sudo tee $WSS_PATH << 'EOF' | cat
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

    def addConn(self, conn):
        with self.threadsLock:
            if self.running:
                self.threads.append(conn)

    def removeConn(self, conn):
        with self.threadsLock:
            if conn in self.threads:
                self.threads.remove(conn)

    def close(self):
        with self.threadsLock:
            self.running = False
            for c in list(self.threads):
                c.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        self.targetClosed = True

    def run(self):
        try:
            data = self.client.recv(BUFLEN)
            hostPort = DEFAULT_HOST
            self.method_CONNECT(hostPort)
        except Exception as e:
            print("Error:", e)
        finally:
            self.close()
            self.server.removeConn(self)

    def method_CONNECT(self, path):
        host, port = path.split(':')
        port = int(port)
        self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target.connect((host, port))
        self.targetClosed = False
        self.client.sendall(RESPONSE.encode())
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        while True:
            try:
                recv, _, _ = select.select(socs, [], [], 3)
                for s in recv:
                    data = s.recv(BUFLEN)
                    if not data:
                        return
                    if s is self.client:
                        self.target.sendall(data)
                    else:
                        self.client.sendall(data)
            except:
                break

def main():
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    print(f"WSS 正在运行，监听端口: {LISTENING_PORT}")
    server.join()

if __name__ == "__main__":
    main()
EOF

sudo chmod +x $WSS_PATH
echo "==== WSS 脚本创建完成，内容如下 ===="
cat $WSS_PATH

# ====== stunnel4 安装与配置 ======
echo "==== 配置 stunnel4 ===="
sudo mkdir -p /etc/stunnel/certs

echo "生成自签证书..."
sudo openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/wss.key \
-out /etc/stunnel/certs/wss.crt \
-days 1095 \
-subj "/CN=example.com"

sudo sh -c 'cat /etc/stunnel/certs/wss.key /etc/stunnel/certs/wss.crt > /etc/stunnel/certs/wss.pem'
sudo chmod 644 /etc/stunnel/certs/*.pem

echo "==== 证书生成完成，CRT 内容如下 ===="
sudo cat /etc/stunnel/certs/wss.crt

echo "创建 stunnel 配置..."
sudo tee /etc/stunnel/ssh-tls.conf << EOF | cat
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
cert = /etc/stunnel/certs/wss.pem
key = /etc/stunnel/certs/wss.pem
connect = 127.0.0.1:22
EOF

echo "==== stunnel 配置完成 ===="
cat /etc/stunnel/ssh-tls.conf

sudo systemctl enable stunnel4
sudo systemctl restart stunnel4
echo "stunnel4 已启动"

# ====== 安装 UDPGW ======
echo "==== 安装 UDPGW ===="
bash <(curl -Ls https://raw.githubusercontent.com/xpanel-cp/XPanel-SSH-User-Management/master/fix-call.sh --ipv4)
echo "UDPGW 安装完成，默认端口: $UDPGW_PORT"

echo "==== 安装完成 ===="
echo "WSS: $WSS_PORT"
echo "stunnel4: $STUNNEL_PORT"
echo "UDPGW: $UDPGW_PORT"
