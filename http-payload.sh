#!/bin/bash

# -----------------------------
# 一键安装脚本 (Ubuntu)
# WSS + UDPGW + TUNNEL4
# -----------------------------

# 默认端口
DEFAULT_WSS_PORT=80
DEFAULT_TUNNEL4_PORT=443
DEFAULT_UDPGW_PORT=7300

# 读取用户输入端口
read -p "请输入 WSS 监听端口 [默认: $DEFAULT_WSS_PORT]: " WSS_PORT
WSS_PORT=${WSS_PORT:-$DEFAULT_WSS_PORT}

read -p "请输入 TUNNEL4 监听端口 [默认: $DEFAULT_TUNNEL4_PORT]: " TUNNEL4_PORT
TUNNEL4_PORT=${TUNNEL4_PORT:-$DEFAULT_TUNNEL4_PORT}

read -p "请输入 UDPGW 监听端口 [默认: $DEFAULT_UDPGW_PORT]: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-$DEFAULT_UDPGW_PORT}

# 等待 apt 解锁函数
wait_for_apt() {
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        echo "等待 apt 解锁中..."
        sleep 3
    done
}

# 安装依赖
install_packages() {
    wait_for_apt
    echo "更新系统..."
    sudo apt update -y || { echo "apt update 失败"; exit 1; }

    wait_for_apt
    echo "安装 Python3、pip、wget、curl、git 等依赖..."
    sudo apt install -y python3 python3-pip wget curl git net-tools || { echo "安装依赖失败"; exit 1; }

    echo "依赖安装完成"
}

# 创建 WSS 脚本
create_wss_script() {
    echo "创建 WSS 脚本..."
    cat >/usr/local/bin/wss <<EOF
#!/usr/bin/python3
import socket, threading, select, sys, time

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = $WSS_PORT
BUFLEN = 4096*4
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
            self.threads.remove(conn)

    def close(self):
        with self.threadsLock:
            threads = list(self.threads)
            for c in threads:
                c.close()
        self.running = False

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
            if hostPort != '':
                self.method_CONNECT(hostPort)
            else:
                self.client.send(b'HTTP/1.1 400 NoXRealHost!\\r\\n\\r\\n')
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
        aux = head.find('\\r\\n')
        if aux == -1:
            return ''
        return head[:aux]

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
        self.client_buffer = ''
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
            if count == TIMEOUT:
                error = True
            if error:
                break

def main():
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

    sudo chmod +x /usr/local/bin/wss
    echo "WSS 脚本创建完成，可直接运行: sudo /usr/local/bin/wss"
}

# 安装 UDPGW
install_udpgw() {
    echo "安装 UDPGW..."
    bash <(curl -Ls https://raw.githubusercontent.com/xpanel-cp/XPanel-SSH-User-Management/master/fix-call.sh) $UDPGW_PORT
    echo "UDPGW 安装完成"
}

# 安装 TUNNEL4
install_tunnel4() {
    echo "安装 TUNNEL4..."
    bash <(curl -Ls https://raw.githubusercontent.com/xiaoguiday/http-payload/refs/heads/main/http-payload.sh) $TUNNEL4_PORT
    echo "TUNNEL4 安装完成"
}

# -----------------------------
# 执行顺序
# -----------------------------
install_packages
create_wss_script
install_udpgw
install_tunnel4

echo "所有服务安装完成！"
echo "WSS 端口: $WSS_PORT"
echo "TUNNEL4 端口: $TUNNEL4_PORT"
echo "UDPGW 端口: $UDPGW_PORT"
