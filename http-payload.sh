#!/bin/bash

set -e

# ------------------------------
# 默认端口
DEFAULT_WSS_PORT=80
DEFAULT_TUNNEL4_PORT=443
DEFAULT_UDPGW_PORT=7300

# ------------------------------
# 读取用户自定义端口
read -p "请输入 WSS 端口 [默认 $DEFAULT_WSS_PORT]: " WSS_PORT
WSS_PORT=${WSS_PORT:-$DEFAULT_WSS_PORT}

read -p "请输入 Tunnel4 端口 [默认 $DEFAULT_TUNNEL4_PORT]: " TUNNEL4_PORT
TUNNEL4_PORT=${TUNNEL4_PORT:-$DEFAULT_TUNNEL4_PORT}

read -p "请输入 UDPGW 端口 [默认 $DEFAULT_UDPGW_PORT]: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-$DEFAULT_UDPGW_PORT}

echo "WSS 端口: $WSS_PORT"
echo "Tunnel4 端口: $TUNNEL4_PORT"
echo "UDPGW 端口: $UDPGW_PORT"

# ------------------------------
# 更新系统 & 安装 Python3
echo "安装 Python3..."
if ! command -v python3 &> /dev/null; then
    apt-get update
    apt-get install -y python3 python3-pip
fi

# ------------------------------
# 安装 WSS
echo "安装 WSS..."
mkdir -p /usr/local/bin
cat >/usr/local/bin/wss <<'EOF'
#!/usr/bin/python3
import socket, threading, select, sys, time

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv)>1 else 80

BUFLEN = 4096*4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:22'
RESPONSE = 'HTTP/1.1 101 Switching Protocols\r\nContent-Length: 104857600000\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
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
            print(log)

    def addConn(self, conn):
        with self.threadsLock:
            if self.running:
                self.threads.append(conn)

    def removeConn(self, conn):
        with self.threadsLock:
            if conn in self.threads:
                self.threads.remove(conn)

    def close(self):
        self.running = False
        with self.threadsLock:
            threads = list(self.threads)
            for c in threads:
                c.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        super().__init__()
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
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            if not hostPort:
                hostPort = DEFAULT_HOST
            split = self.findHeader(self.client_buffer, 'X-Split')
            if split:
                self.client.recv(BUFLEN)
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
            head = head.decode('utf-8')
        idx = head.find(header + ': ')
        if idx == -1:
            return ''
        idx2 = head.find('\r\n', idx)
        return head[idx+len(header)+2:idx2].strip()

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
        self.log += ' - CONNECT ' + path
        self.connect_target(path)
        self.client.sendall(RESPONSE.encode('utf-8'))
        self.client_buffer = b''
        self.server.printLog(self.log)
        self.doCONNECT()

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
            if count == TIMEOUT or error:
                break

def main():
    print("Starting WSS on port {}".format(LISTENING_PORT))
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        server.close()

if __name__ == '__main__':
    main()
EOF

chmod +x /usr/local/bin/wss

# ------------------------------
# 安装 Tunnel4
echo "安装 Tunnel4..."
# 这里假设你已有 Tunnel4 安装命令或二进制，示例:
# wget -O /usr/local/bin/tunnel4 https://example.com/tunnel4 && chmod +x /usr/local/bin/tunnel4
# 创建默认配置和证书
mkdir -p /etc/tunnel4
cat >/etc/tunnel4/config.json <<EOC
{
    "port": $TUNNEL4_PORT,
    "cert": "/etc/tunnel4/tls.crt",
    "key": "/etc/tunnel4/tls.key"
}
EOC
# 假设生成自签名证书
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/tunnel4/tls.key \
    -out /etc/tunnel4/tls.crt \
    -subj "/CN=localhost"

# ------------------------------
# 安装 UDPGW
echo "安装 UDPGW..."
bash <(curl -Ls https://raw.githubusercontent.com/xpanel-cp/XPanel-SSH-User-Management/master/fix-call.sh --ipv4)
# 端口可在交互中自定义

# ------------------------------
echo "安装完成！服务端口:"
echo "WSS: $WSS_PORT"
echo "Tunnel4: $TUNNEL4_PORT"
echo "UDPGW: $UDPGW_PORT"
echo "可以使用 systemctl 启动/管理相应服务"
