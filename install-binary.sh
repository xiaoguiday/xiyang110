#!/bin/bash

# =================================================================
# WSTunnel-Go (二进制版) 全自动一键安装/更新脚本 (带清理功能)
# 更新时间:2025-10-13-10-13
# 版本: 2.0
# =================================================================

set -e

# --- 脚本设置 ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- 项目配置 (请务必更新这里的二进制文件下载链接) ---
BINARY_URL="https://raw.githubusercontent.com/xiaoguiday/jiating/main/wstunnel-go"
HTML_URL="https://raw.githubusercontent.com/xiaoguiday/jiating/main/admin.html"

SERVICE_NAME="wstunnel"
BINARY_NAME="wstunnel-go"
DEPLOY_DIR="/usr/local/bin"

# --- 函数定义 ---
info() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error_exit() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

# 新增的清理函数
cleanup_old_versions() {
    info "正在检查并清理旧的编译目录..."
    
    # 定义可能的旧源代码目录
    OLD_SRC_DIRS=("$HOME/go_wstunnel" "/root/go_wstunnel" "/usr/local/src/go_wstunnel")

    for dir in "${OLD_SRC_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            warn "发现旧的编译目录: ${dir}，正在删除..."
            rm -rf "$dir"
            info "已删除 ${dir}。"
        fi
    done
    info "旧版本清理完成。"
    echo " "
}


# --- 脚本主逻辑 ---

# 1. 权限检查
info "第 1 步: 正在检查运行权限..."
if [ "$(id -u)" != "0" ]; then
   error_exit "此脚本需要以 root 权限运行。请使用 'sudo bash' 来执行。"
fi
info "权限检查通过。"
echo " "

# 2. 安装必要工具
info "第 2 步: 正在安装必要的工具 (wget, curl, tar)..."
apt-get update -y > /dev/null
apt-get install -y wget curl tar > /dev/null || error_exit "安装必要工具失败！"
info "工具已准备就绪。"
echo " "

# 2.5 清理旧版本
cleanup_old_versions

# 3. 下载预编译的二进制文件和模板
info "第 3 步: 正在下载预编译的程序文件..."
# 创建一个临时目录进行下载，避免污染当前目录
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR" || error_exit "创建临时目录失败！"

curl -sS -L -o "${BINARY_NAME}" "${BINARY_URL}" || error_exit "下载二进制文件失败！请检查链接是否正确。"
curl -sS -L -o "admin.html" "${HTML_URL}" || error_exit "下载 admin.html 失败！"
info "文件下载成功。"
echo " "

# 4. 部署文件
info "第 4 步: 正在部署文件到 ${DEPLOY_DIR}/ ..."
chmod +x ./${BINARY_NAME} || error_exit "添加执行权限失败！"
# 先停止服务，再移动文件，防止文件正在使用中
systemctl stop ${SERVICE_NAME}.service || true
mv ./${BINARY_NAME} ${DEPLOY_DIR}/ || error_exit "移动 ${BINARY_NAME} 失败！"
mv ./admin.html ${DEPLOY_DIR}/ || error_exit "移动 admin.html 失败！"
info "文件部署成功。"
echo " "

# 5. 创建并启用 systemd 服务
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
info "第 5 步: 正在配置 systemd 服务..."
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

# 6. 启动/重启服务并检查状态
info "第 6 步: 正在启动/重启服务..."
systemctl restart ${SERVICE_NAME}.service || error_exit "服务启动/重启失败！"
info "操作成功。"
echo " "

# 7. 最终确认
info "🎉 全部成功！WSTunnel-Go 已安装/更新并正在运行。"
# 清理临时下载目录
rm -rf "$TEMP_DIR"
echo " "
info "正在检查最终服务状态 (等待2秒)..."
sleep 2
systemctl status ${SERVICE_NAME}.service
