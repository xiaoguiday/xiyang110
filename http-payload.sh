#!/bin/bash
set -e

# 默认端口
WSS_PORT=80
UDPGW_PORT=7300
STUNNEL_PORT=443

echo "=============================="
echo "  VPS 一键安装 WSS/UDPGW/Stunnel"
echo "=============================="

# 用户输入端口（可直接回车使用默认）
read -p "请输入 WSS 监听端口（默认 80）: " input
[ ! -z "$input" ] && WSS_PORT=$input

read -p "请输入 UDPGW 端口（默认 7300）: " input
[ ! -z "$input" ] && UDPGW_PORT=$input

read -p "请输入 Stunnel 监听端口（默认 443）: " input
[ ! -z "$input" ] && STUNNEL_PORT=$input

echo "使用端口: WSS=$WSS_PORT, UDPGW=$UDPGW_PORT, Stunnel=$STUNNEL_PORT"

# 等待 apt 可用
wait_for_apt() {
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 ; do
        echo "正在等待其他 apt/dpkg 进程完成..."
        sleep 3
    done
}

# 更新系统并安装依赖
install_packages() {
    wait_for_apt
    echo "更新系统..."
    sudo apt update -y && sudo apt upgrade -y

    echo "安装 Python3、pip、wget、curl、git、net-tools 等依赖..."
    sudo apt install -y python3 python3-pip wget curl git net-tools
    echo "依赖安装完成"
}

# 创建 WSS 脚本
install_wss() {
    echo "==== 安装 WSS 脚本 ===="
    mkdir -p ~/wss
    cat > ~/wss/wss.py <<EOF
#!/usr/bin/python3
import socket, threading, select, sys, time

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else $WSS_PORT

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
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True
        print(f"WSS 监听在 {self.host}:{self.port}")
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
            for c in self.threads:
                c.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.server = server
        self.addr = addr

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
            self.connect_target(hostPort)
            self.client.sendall(RESPONSE.encode('utf-8'))
            self.doCONNECT()
        except Exception as e:
            self.server.printLog(f"连接 {self.addr} 出错: {e}")
        finally:
            self.close()
            self.server.removeConn(self)

    def connect_target(self, host):
        ip, port = host.split(':')
        port = int(port)
        self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target.connect((ip, port))
        self.targetClosed = False

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            r, _, err = select.select(socs, [], socs, 3)
            if err:
                error = True
            if r:
                for s in r:
                    try:
                        d = s.recv(BUFLEN)
                        if d:
                            if s is self.target:
                                self.client.send(d)
                            else:
                                while d:
                                    sent = self.target.send(d)
                                    d = d[sent:]
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

if __name__ == "__main__":
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        time.sleep(2)
EOF
    chmod +x ~/wss/wss.py
    echo "WSS 脚本创建完成: ~/wss/wss.py"
}

# 安装 Stunnel4 并生成自签名证书
install_stunnel() {
    echo "==== 安装 Stunnel4 ===="
    sudo apt install -y stunnel4 openssl
    sudo mkdir -p /etc/stunnel/certs

    # 自动生成证书
    CERT_PATH="/etc/stunnel/certs/stunnel.pem"
    sudo openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /etc/stunnel/certs/stunnel.key \
        -out /etc/stunnel/certs/stunnel.crt \
        -days 1095 \
        -subj "/CN=localhost"

    sudo sh -c "cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > $CERT_PATH"
    sudo chmod 644 /etc/stunnel/certs/*.pem

    # 配置 stunnel
    CONF_PATH="/etc/stunnel/ssh-tls.conf"
    sudo bash -c "cat > $CONF_PATH" <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls]
accept = 0.0.0.0:$STUNNEL_PORT
cert = $CERT_PATH
key = $CERT_PATH
connect = 127.0.0.1:22
EOF

    sudo systemctl enable stunnel4
    sudo systemctl restart stunnel4
    echo "Stunnel4 安装完成，监听端口: $STUNNEL_PORT"
}

# 安装 UDPGW
install_udpgw() {
    echo "==== 安装 UDPGW ===="
    bash <(curl -Ls https://raw.githubusercontent.com/xpanel-cp/XPanel-SSH-User-Management/master/fix-call.sh --ipv4)
    echo "UDPGW 安装完成，默认端口: $UDPGW_PORT"
}

# 执行安装
install_packages
install_wss
install_stunnel
install_udpgw

echo "=============================="
echo "安装完成！"
echo "WSS 脚本路径: ~/wss/wss.py"
echo "UDPGW 端口: $UDPGW_PORT"
echo "Stunnel 监听端口: $STUNNEL_PORT"
echo "=============================="
