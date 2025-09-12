#!/bin/bash
set -e

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
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4
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
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
PASS = ''
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
        self.logLock.acquire()
        print(log)
        self.logLock.release()
    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()
    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()
    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()
            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)
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
            self.client_buffer = self.client.recv(BUFLEN)
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            if hostPort == '':
                hostPort = DEFAULT_HOST
            passwd = self.findHeader(self.client_buffer, 'X-Pass')
            if len(PASS) != 0 and passwd != PASS:
                self.client.send(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                return
            self.method_CONNECT(hostPort)
        except Exception as e:
            self.log += ' - error: ' + str(e)
            self.server.printLog(self.log)
        finally:
            self.close()
            self.server.removeConn(self)
    def findHeader(self, head, header):
        if isinstance(head, bytes):
            head = head.decode('utf-8')
        aux = head.find(header + ': ')
        if aux == -1:
            return ''
        aux = head.find(':', aux)
        head = head[aux + 2:]
        aux = head.find('\r\n')
        if aux == -1:
            return ''
        return head[:aux]
    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i + 1:])
            host = host[:i]
        else:
            port = 22
        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]
        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)
    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        self.connect_target(path)
        self.client.sendall(RESPONSE.encode('utf-8'))
        self.client_buffer = ''
        self.server.printLog(self.log)
        self.doCONNECT()
    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
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
                                    byte = self.target.send(data)
                                    data = data[byte:]
                            count = 0
                        else:
                            break
                    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break

def main():
    print("\n:-------PythonProxy WSS-------:\n")
    print(f"Listening addr: {LISTENING_ADDR}, port: {LISTENING_PORT}\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print('Stopping...')
            server.close()
            break

if __name__ == '__main__':
    main()
EOF

sudo chmod +x /usr/local/bin/wss
echo "WSS 脚本安装完成"
echo "----------------------------------"

# 创建 systemd 服务
sudo tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wss $WSS_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

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
-days 1095 \
-subj "/CN=example.com"
sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
sudo chmod 644 /etc/stunnel/certs/*.crt
sudo chmod 644 /etc/stunnel/certs/*.pem

# Stunnel 配置
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
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:22
EOF

sudo systemctl enable stunnel4
sudo systemctl restart stunnel4
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

# 创建 systemd 服务（修正绑定地址为 127.0.0.1）
sudo tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
Type=simple
ExecStart=/root/badvpn/badvpn-build/udpgw/badvpn-udpgw --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1024 --max-connections-for-client 10
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable udpgw
sudo systemctl start udpgw
echo "UDPGW 已安装并启动，端口: $UDPGW_PORT"
echo "----------------------------------"

echo "所有组件安装完成!"
echo "查看 WSS 状态: sudo systemctl status wss"
echo "查看 Stunnel4 状态: sudo systemctl status stunnel4"
echo "查看 UDPGW 状态: sudo systemctl status udpgw"
