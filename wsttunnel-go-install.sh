#!/bin/bash

# =================================================================
# WSTunnel-Go 全自动一键安装/更新脚本 (健壮版)
# 作者: xiaoguidays
# 更新时间: 2025-10-14
# 版本: 1.2
# 更新内容: 增加对 login.html 的下载和部署
# =================================================================

set -e # 任何命令失败，脚本立即退出

# --- 脚本设置 ---
# 颜色代码
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 项目配置
GO_VERSION="1.22.3"
PROJECT_DIR="/usr/local/src/go_wstunnel" # 使用一个标准的源代码目录
GITHUB_REPO="xiaoguiday/xiyang110"
SERVICE_NAME="wstunnel"
BINARY_NAME="wstunnel-go"
DEPLOY_DIR="/usr/local/bin"

# --- 函数定义 ---
info() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error_exit() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

# --- 脚本主逻辑 ---

# 1. 权限检查
info "第 1 步: 正在检查运行权限..."
if [ "$(id -u)" != "0" ]; then
   error_exit "此脚本需要以 root 权限运行。请使用 'sudo' 或以 root 用户执行。"
fi
info "权限检查通过。"
echo " "

# 2. 安装必要的工具
info "第 2 步: 正在安装必要的工具 (wget, curl, tar, git)..."
apt-get update -y > /dev/null
apt-get install -y wget curl tar git > /dev/null || error_exit "安装必要工具失败！"
info "工具已准备就绪。"
echo " "

# 3. 安装 Go 语言环境
info "第 3 步: 正在检查并安装 Go 语言环境..."
if ! command -v go &> /dev/null || [[ ! $(go version) == *"go${GO_VERSION}"* ]]; then
    warn "未找到 Go 环境或版本不匹配。正在安装 Go ${GO_VERSION}..."
    wget -q -O go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" || error_exit "下载 Go 安装包失败！"
    rm -rf /usr/local/go && tar -C /usr/local -xzf go.tar.gz || error_exit "解压 Go 安装包失败！"
    rm go.tar.gz

    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    # 立即生效
    export PATH=$PATH:/usr/local/go/bin
    info "Go ${GO_VERSION} 安装成功！"
else
    info "Go 环境已存在且版本正确。"
fi
# 再次验证
if ! command -v go &> /dev/null; then
    error_exit "Go 命令在当前会话中不可用。请尝试运行 'source /etc/profile' 然后重新运行脚本。"
fi
go version
echo " "

# 4. 创建项目目录并拉取文件
info "第 4 步: 正在准备项目目录并拉取最新代码..."
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR" || error_exit "进入项目目录 '$PROJECT_DIR' 失败！"

# 同时下载三个必需的文件
wget -q -O main.go "https://raw.githubusercontent.com/${GITHUB_REPO}/main/main.go" || error_exit "下载 main.go 失败！"
wget -q -O admin.html "https://raw.githubusercontent.com/${GITHUB_REPO}/main/admin.html" || error_exit "下载 admin.html 失败！"
# --- [新増] 下载 login.html ---
wget -q -O login.html "https://raw.githubusercontent.com/${GITHUB_REPO}/main/login.html" || error_exit "下载 login.html 失败！"
info "最新代码拉取成功。"
echo " "

# 5. 编译项目
info "第 5 步: 正在编译项目 (位于 ${PROJECT_DIR})..."
if [ ! -f "go.mod" ]; then
    go mod init wstunnel || error_exit "go mod init 失败！"
fi
go mod tidy || error_exit "go mod tidy 失败！"
go build -o ${BINARY_NAME} || error_exit "编译失败！"
info "项目编译成功。"
echo " "

# 6. 部署文件
info "第 6 步: 正在部署文件到 ${DEPLOY_DIR}/ ..."
# 移动可执行文件
mv ./${BINARY_NAME} ${DEPLOY_DIR}/ || error_exit "移动 ${BINARY_NAME} 失败！"
# 移动网页文件
mv ./admin.html ${DEPLOY_DIR}/ || error_exit "移动 admin.html 失败！"
# --- [新増] 移动 login.html ---
mv ./login.html ${DEPLOY_DIR}/ || error_exit "移动 login.html 失败！"
info "文件部署成功。"
echo " "

# 7. 创建并启用 systemd 服务
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
info "第 7 步: 正在配置 systemd 服务..."
# 无论是否存在都覆盖，以确保配置是最新版本
cat > "$SERVICE_FILE" <<EOT
[Unit]
Description=WSTunnel-Go Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${DEPLOY_DIR}
ExecStart=${DEPLOY_DIR}/${BINARY_NAME}
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOT

systemctl daemon-reload || error_exit "systemctl daemon-reload 失败！"
systemctl enable ${SERVICE_NAME}.service || error_exit "systemctl enable 失败！"
info "服务配置完成并已启用。"
echo " "

# 8. 启动/重启服务并检查状态
info "第 8 步: 正在启动/重启服务..."
systemctl restart ${SERVICE_NAME}.service || error_exit "服务启动/重启失败！"
info "操作成功。"
echo " "

# 最终确认
info "🎉 全部成功！WSTunnel-Go 已安装/更新并正在运行。"
echo " "
info "正在检查最终服务状态 (等待2秒)..."
sleep 2
systemctl status ${SERVICE_NAME}.service
