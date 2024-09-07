#!/bin/bash

# 定义版本号
VERSION="1.3.5"

# 定义配置文件路径
CONFIG_FILE="/root/.eth_bls_config"

# 加载配置
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        # 默认配置
        VENV_PATH="/root/.venv/eth_bls_env"
        OUTPUT_DIR="/root/.local/eth_bls_output"
        LOG_FILE="$OUTPUT_DIR/eth_bls_key_gen.log"
        ETH_PRIVATE_KEYS_FILE="$OUTPUT_DIR/1_eth_private_keys.txt"
        ETH_PUBLIC_KEYS_FILE="$OUTPUT_DIR/2_eth_public_keys.txt"
        BLS_PRIVATE_KEYS_FILE="$OUTPUT_DIR/3_bls_private_keys.txt"
        BLS_PUBLIC_KEYS_FILE="$OUTPUT_DIR/4_bls_public_keys.txt"
        COMBINED_KEYS_FILE="$OUTPUT_DIR/5_combined_keys.txt"
        
        # 保存默认配置
        mkdir -p "$(dirname "$CONFIG_FILE")"
        cat > "$CONFIG_FILE" <<EOL
VENV_PATH="$VENV_PATH"
OUTPUT_DIR="$OUTPUT_DIR"
LOG_FILE="$LOG_FILE"
ETH_PRIVATE_KEYS_FILE="$ETH_PRIVATE_KEYS_FILE"
ETH_PUBLIC_KEYS_FILE="$ETH_PUBLIC_KEYS_FILE"
BLS_PRIVATE_KEYS_FILE="$BLS_PRIVATE_KEYS_FILE"
BLS_PUBLIC_KEYS_FILE="$BLS_PUBLIC_KEYS_FILE"
COMBINED_KEYS_FILE="$COMBINED_KEYS_FILE"
EOL
    fi
}

# 加载配置
load_config

# 创建输出目录如果不存在
mkdir -p "$OUTPUT_DIR"

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# 错误处理函数
handle_error() {
    log "错误: $1"
    exit 1
}

# 更新系统功能，刷新软件列表清单
update_system() {
    log "正在更新系统..."
    if apt update && apt upgrade -y; then
        log "系统更新完成。"
    else
        handle_error "系统更新失败，请检查您的网络连接和系统权限。"
    fi
}

# 检测并确保Python 3.10和pip已安装
ensure_python_and_pip_installed() {
    if ! command -v python3.10 &> /dev/null || ! command -v pip3 &> /dev/null; then
        log "Python 3.10和pip未安装，正在尝试安装..."
        if apt update && apt install -y software-properties-common && \
           add-apt-repository -y ppa:deadsnakes/ppa && \
           apt update && \
           apt install -y python3.10 python3.10-venv python3-pip; then
            log "Python 3.10, pip 和 venv 安装成功。"
            update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1
            update-alternatives --set python3 /usr/bin/python3.10
        else
            handle_error "Python 3.10, pip 和 venv 安装失败，请手动安装。"
        fi
    fi
    log "Python版本: $(python3.10 --version)"
}

# 创建并激活虚拟环境
create_and_activate_venv() {
    if [[ ! -d "$VENV_PATH" ]]; then
        log "创建虚拟环境..."
        python3.10 -m venv "$VENV_PATH"
    fi
    log "激活虚拟环境..."
    source "$VENV_PATH/bin/activate"
}

# 检测并确保必要的库已安装
ensure_libraries_installed() {
    create_and_activate_venv
    log "检查必要库的安装..."
    if ! python3.10 -c "import py_ecc" &> /dev/null || ! python3.10 -c "import eth_keys" &> /dev/null; then
        log "必要库未找到，尝试安装..."
        if pip3 install py_ecc==6.0.0 eth_keys==0.4.0; then
            log "必要库安装成功。"
        else
            handle_error "必要库安装失败。请检查您的网络连接和Python环境。"
        fi
    fi
    log "必要库已安装。版本信息:"
    pip3 list | grep -E "py_ecc|eth_keys" | tee -a "$LOG_FILE"
}

# 检查所有生成密钥的准备工作
check_all_prerequisites() {
    log "正在检查所有生成密钥的准备工作..."
    
    update_system
    ensure_python_and_pip_installed
    ensure_libraries_installed
    
    log "所有准备工作已完成，可以开始生成密钥。"
}

# 从以太坊私钥生成所有相关密钥
generate_all_keys() {
    local eth_private_key="$1"
    eth_private_key=$(echo $eth_private_key | sed 's/^0x//') # 去除可能的0x前缀
    local result
    result=$("$VENV_PATH/bin/python3.10" -c '
import sys
from py_ecc import bls
from py_ecc.bls import G2ProofOfPossession
from eth_keys import keys
import secrets
import traceback

def int_to_hex(x):
    return hex(x)[2:].zfill(64)

try:
    print("Debug: Starting key generation process", file=sys.stderr)
    eth_private_key = bytes.fromhex("'"$eth_private_key"'")
    print(f"Debug: Ethereum private key: {eth_private_key.hex()}", file=sys.stderr)
    
    eth_key = keys.PrivateKey(eth_private_key)
    eth_public_key = eth_key.public_key
    print(f"Debug: Ethereum public key: {eth_public_key.to_hex()}", file=sys.stderr)

    # Generate a new random BLS private key
    bls_private_key = G2ProofOfPossession.KeyGen(secrets.token_bytes(32))
    print(f"Debug: BLS private key: {hex(bls_private_key)}", file=sys.stderr)

    # Generate BLS public key
    bls_public_key = G2ProofOfPossession.SkToPk(bls_private_key)
    bls_public_key_hex = "0x" + bls_public_key.hex()
    print(f"Debug: BLS public key: {bls_public_key_hex}", file=sys.stderr)

    eth_priv_hex = "0x" + eth_private_key.hex()
    eth_pub_hex = eth_public_key.to_hex()
    bls_priv_hex = "0x" + int_to_hex(bls_private_key)

    print(f"{eth_priv_hex}|{eth_pub_hex}|{bls_priv_hex}|{bls_public_key_hex}")
    print("Debug: Key generation completed successfully", file=sys.stderr)
except Exception as e:
    print(f"Error: {str(e)}", file=sys.stderr)
    print("Traceback:", file=sys.stderr)
    print(traceback.format_exc(), file=sys.stderr)
    sys.exit(1)
' 2>&1)
    local exit_code=$?
    echo "Debug: Python script exit code: $exit_code" >&2
    echo "Debug: Python script output:" >&2
    echo "$result" >&2
    if [ $exit_code -eq 0 ]; then
        echo "$result" | grep -v "^Debug:" | grep -v "^Error:" | grep -v "^Traceback:"
    else
        return 1
    fi
}

# 验证以太坊私钥格式
validate_eth_private_key() {
    local key="$1"
    if [[ ! "$key" =~ ^(0x)?[0-9a-fA-F]{64}$ ]]; then
        return 1
    fi
    return 0
}

# 批量生成并保存所有密钥
batch_generate_all_keys() {
    create_and_activate_venv
    log "开始批量生成所有密钥..."
    # 清空所有输出文件
    > "$ETH_PRIVATE_KEYS_FILE"
    > "$ETH_PUBLIC_KEYS_FILE"
    > "$BLS_PRIVATE_KEYS_FILE"
    > "$BLS_PUBLIC_KEYS_FILE"
    > "$COMBINED_KEYS_FILE"

    echo "请粘贴以太坊私钥（可以一次性粘贴多个，每行一个），然后按回车两次确认录入："
    
    temp_input_file=$(mktemp)
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -z "$line" ]]; then
            break
        fi
        echo "$line" >> "$temp_input_file"
    done

    total_keys=$(wc -l < "$temp_input_file")
    current_key=0

    while IFS= read -r eth_private_key; do
        current_key=$((current_key + 1))
        log "处理第 $current_key / $total_keys 个密钥"
        
        if ! validate_eth_private_key "$eth_private_key"; then
            log "警告: 无效的以太坊私钥格式: $eth_private_key. 跳过此密钥。"
            continue
        fi
        
        log "当前处理的以太坊私钥: $eth_private_key"
        result=$(generate_all_keys "$eth_private_key")
        exit_code=$?
        log "generate_all_keys 函数返回码: $exit_code"
        log "generate_all_keys 函数输出:"
        log "$result"
        if [[ $exit_code -eq 0 ]]; then
            valid_result=$(echo "$result" | grep -v "^Debug:" | grep -v "^Error:" | grep -v "^Traceback:")
            if [[ -n "$valid_result" ]]; then
                IFS='|' read -r eth_private_key eth_pub bls_priv bls_pub <<< "$valid_result"
                echo "$eth_private_key" >> "$ETH_PRIVATE_KEYS_FILE"
                echo "$eth_pub" >> "$ETH_PUBLIC_KEYS_FILE"
                echo "$bls_priv" >> "$BLS_PRIVATE_KEYS_FILE"
                echo "$bls_pub" >> "$BLS_PUBLIC_KEYS_FILE"
                echo "ETH私钥: $eth_private_key, ETH公钥: $eth_pub, BLS私钥: $bls_priv, BLS公钥: $bls_pub" >> "$COMBINED_KEYS_FILE"
                log "成功生成所有密钥: ETH私钥: $eth_private_key"
            else
                log "生成失败，未能解析有效结果"
            fi
        else
            log "生成失败，跳过以太坊私钥: $eth_private_key"
            log "错误详情: $result"
        fi
        echo -ne "进度: $((current_key * 100 / total_keys))%\r"
    done < "$temp_input_file"

    rm "$temp_input_file"

    log "所有密钥已保存至 $OUTPUT_DIR 目录下的相应文件中。"
}

# 移除脚本和相关文件
remove_script_and_files() {
    log "警告：此操作将移除所有相关文件和输出目录 '$OUTPUT_DIR'。"
    read -p "您确定要继续吗？(y/n): " confirmation
    if [[ "$confirmation" =~ ^[Yy] ]]; then
        log "正在创建备份..."
        backup_dir="/root/eth_bls_backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$backup_dir"
        cp -R "$OUTPUT_DIR" "$backup_dir"
        log "备份已创建: $backup_dir"
        
        rm -rf "$OUTPUT_DIR" "$VENV_PATH" "$CONFIG_FILE"
        log "所有相关文件和目录已被删除。"
    else
        log "删除操作已取消。"
    fi
}

# 检查更新
check_for_updates() {
    log "正在检查更新..."
    # 这里应该实现实际的更新检查逻辑
    # 例如，从某个URL下载最新版本信息并比较
    log "当前版本: $VERSION"
    log "更新检查完成。"
}

# 显示主菜单
show_menu() {
    echo "欢迎使用以太坊和BLS密钥生成工具 (版本 $VERSION)"
    echo "1. 更新系统"
    echo "2. 确保Python 3.10和pip已安装"
    echo "3. 确保必要库已安装"
    echo "4. 检查所有生成密钥准备工作"
    echo "5. 批量生成所有密钥"
    echo "6. 移除脚本和所有相关文件"
    echo "7. 检查更新"
    echo "8. 退出"
}

# 主循环
main_loop() {
    while true; do
        show_menu
        read -p "请输入选项 [1-8]: " option
        case $option in
            1) update_system ;;
            2) ensure_python_and_pip_installed ;;
            3) ensure_libraries_installed ;;
            4) check_all_prerequisites ;;
            5) batch_generate_all_keys ;;
            6) remove_script_and_files ;;
            7) check_for_updates ;;
            8) 
                deactivate 2>/dev/null
                log "程序退出。"
                exit 0 
                ;;
            *) log "无效的选项，请重新输入。" ;;
        esac
        echo
    done
}

# 启动脚本
main_loop
