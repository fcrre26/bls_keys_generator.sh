#!/bin/bash

# 定义输出目录和虚拟环境目录
OUTPUT_DIR="${HOME}/.local/bls-output"
VIRTUAL_ENV_DIR="${OUTPUT_DIR}/venv"
TEMP_DIR="${OUTPUT_DIR}/temp"
LOG_DIR="${OUTPUT_DIR}/logs"

# 定义私钥、公钥和组合密钥的文件路径
PRIVATE_KEYS_FILE="${OUTPUT_DIR}/private_keys.txt"
ETHEREUM_PUBLIC_KEYS_FILE="${OUTPUT_DIR}/ethereum_public_keys.txt"
BLS_PRIVATE_KEYS_FILE="${OUTPUT_DIR}/bls_private_keys.txt"
BLS_PUBLIC_KEYS_FILE="${OUTPUT_DIR}/bls_public_keys.txt"
COMBINED_KEYS_FILE="${OUTPUT_DIR}/combined_keys.txt"

# 定义日志文件路径
LOG_FILE="${LOG_DIR}/script.log"

# 定义所需的 Python 依赖项列表
PYTHON_PACKAGES=("eth-account" "blspy")

# 日志记录函数
echo_to_log() {
    local message=$1
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

# 检查 Python3 版本
check_python_version() {
    local python_version
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    # 使用 Python 的版本比较
    python3 << EOF
import sys
from distutils.version import LooseVersion

required_version = "3.6"
current_version = "$python_version"

if LooseVersion(current_version) < LooseVersion(required_version):
    echo_to_log(f"错误：需要 Python {required_version} 或更高版本。")
    echo_to_log(f"当前 Python 版本为：{current_version}")
    sys.exit(1)
else:
    echo_to_log(f"Python 版本检查通过：{current_version}")
EOF
}

# 检查并安装所需的系统工具和库
install_system_dependencies() {
    echo "检查并安装所需的系统工具和库..."
    local packages=("git" "cmake" "build-essential" "libssl-dev" "python3-pip")
    sudo apt-get update
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -qw "$package"; then
            echo_to_log "$package 未安装，正在尝试安装..."
            sudo apt-get install -y "$package" || { echo_to_log "安装 $package 失败。"; return 1; }
        else
            echo_to_log "$package 已安装。"
        fi
    done
    echo_to_log "所有依赖已安装。"
}

# 创建虚拟环境并安装 Python 依赖项
setup_virtual_environment() {
    echo "创建虚拟环境..."
    if [ ! -d "$VIRTUAL_ENV_DIR" ]; then
        python3 -m venv "$VIRTUAL_ENV_DIR" || { echo_to_log "创建虚拟环境失败。"; return 1; }
    fi
    source "${VIRTUAL_ENV_DIR}/bin/activate"
    echo "激活虚拟环境..."
    if [ $? -ne 0 ]; then
        echo_to_log "激活虚拟环境失败。"
        return 1
    fi
    echo_to_log "确保 pip 是最新的..."
    pip3 install --upgrade pip || { echo_to_log "升级 pip 失败。"; return 1; }
    echo_to_log "安装依赖项..."
    pip3 install "${PYTHON_PACKAGES[@]}" || { echo_to_log "安装依赖项失败。"; return 1; }
    echo_to_log "虚拟环境设置完毕。"
}

# 使用 eth-account 库在虚拟环境中生成以太坊公钥
generate_ethereum_public_key() {
    local private_key=$1
    local public_key
    public_key=$("$VIRTUAL_ENV_DIR/bin/python3" -c "from eth_account import Account; acct = Account.from_key('$private_key'); print(acct.address)" 2>/dev/null)
    echo "$public_key"
}

# 使用 blspy 库在虚拟环境中生成 BLS 私钥
generate_bls_private_key() {
    local ethereum_public_key=$1
    local bls_private_key
    bls_private_key=$("$VIRTUAL_ENV_DIR/bin/python3" -c "from blspy import G1Element, PrivateKey; bls_private_key = PrivateKey.from_seed('$ethereum_public_key'.encode()); print(bls_private_key.to_bytes().hex())" 2>/dev/null)
    echo "$bls_private_key"
}

# 使用 blspy 库在虚拟环境中生成 BLS 公钥
generate_bls_public_key() {
    local bls_private_key=$1
    local bls_public_key
    bls_public_key=$("$VIRTUAL_ENV_DIR/bin/python3" -c "from blspy import G1Element, PrivateKey; bls_private_key = PrivateKey.from_bytes(bytes.fromhex('$bls_private_key')); print(bls_private_key.get_g1().serialize().hex())" 2>/dev/null)
    echo "$bls_public_key"
}

# 并行生成 BLS 公钥的辅助函数
generate_keys_in_parallel() {
    local start_index=$1
    local end_index=$2
    for ((i=start_index; i<=end_index; i++)); do
        local private_key="${private_keys[i]}"
        local ethereum_public_key=$(generate_ethereum_public_key "$private_key")
        local bls_private_key=$(generate_bls_private_key "$ethereum_public_key")
        local bls_public_key=$(generate_bls_public_key "$bls_private_key")
        echo "${private_key},${ethereum_public_key},${bls_private_key},${bls_public_key}" >> "${TEMP_DIR}/keys_part_$((start_index / keys_per_job)).txt"
    done
}

# 批量生成 BLS 公钥，并保持私钥和公钥的顺序
batch_generate_public_keys() {
    create_output_directory
    mkdir -p "$TEMP_DIR"

    echo "请输入以太坊私钥，每个私钥一行，输入完毕后按回车结束:"
    readarray -t private_keys
    if [ ${#private_keys[@]} -eq 0 ]; then
        echo_to_log "没有输入任何私钥，请重新输入。"
        return 1
    fi
    private_keys=($(printf "%s\n" "${private_keys[@]}" | grep -v '^$'))  # 过滤掉空行

    local num_keys=${#private_keys[@]}
    local keys_per_job=$(($(nproc) * 2))
    local num_jobs=$(( (num_keys + keys_per_job - 1) / keys_per_job ))

    # 创建临时文件存储每个并行任务的结果
    for ((i=0; i<num_jobs; i++)); do
        touch "${TEMP_DIR}/keys_part_$i.txt"
    done

    # 启动并行任务
    for ((i=0; i<num_jobs; i++)); do
        start_index=$(( i * keys_per_job ))
        end_index=$(( (i + 1) * keys_per_job ))
        if (( end_index > num_keys )); then end_index=num_keys; fi

        echo "启动任务 $((i + 1)) / $num_jobs..."
        ( generate_keys_in_parallel "$start_index" "$end_index" ) &
    done

    wait  # 等待所有后台进程完成

    # 合并结果文件
    for ((i=0; i<num_jobs; i++)); do
        cat "${TEMP_DIR}/keys_part_$i.txt" >> "$COMBINED_KEYS_FILE"
        rm "${TEMP_DIR}/keys_part_$i.txt"
    done

    # 将私钥列表保存到文件
    printf "%s\n" "${private_keys[@]}" > "$PRIVATE_KEYS_FILE"
    echo_to_log "私钥列表已保存到 $PRIVATE_KEYS_FILE"

    # 显示进度百分比
    for ((i=0; i<num_keys; i++)); do
        local progress_percentage=$(( (i * 100) / num_keys ))
        echo -ne "\r处理进度: $progress_percentage%"
    done
    echo ""
}

# 创建输出目录
create_output_directory() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR" && echo_to_log "输出目录已创建：$OUTPUT_DIR"
    else
        echo_to_log "输出目录已存在：$OUTPUT_DIR"
    fi
    mkdir -p "$LOG_DIR"
    touch "$LOG_FILE"
}

# 日志记录函数
echo_to_log() {
    local message=$1
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

# 删除脚本所有关联信息与文件
remove_script_and_files() {
    echo "警告：此操作将删除脚本及其相关文件和输出目录 '$OUTPUT_DIR'。"
    read -p "您确定要继续吗？(y/n): " confirmation
    if [[ "$confirmation" == "y" || "$confirmation" == "Y" ]]; then
        rm -rf "$OUTPUT_DIR"
        echo_to_log "删除完成。"
    else
        echo_to_log "删除操作已取消。"
    fi
}

# 主菜单
show_menu() {
    while true; do
        echo "欢迎使用 BLS 公钥生成工具"
        echo "1. 安装系统依赖项"
        echo "2. 设置虚拟环境"
        echo "3. 批量生成 BLS 公钥"
        echo "4. 退出脚本"
        echo "5. 删除脚本所有关联信息与文件"
        read -p "请输入选项 [1-5]: " option
        case $option in
            1) install_system_dependencies;;
            2) setup_virtual_environment;;
            3) batch_generate_public_keys;;
            4) exit 0;;
            5) remove_script_and_files;;
            *) echo "无效的选项，请输入 1-5 之间的数字。";;
        esac
    done
}

# 脚本入口点
check_python_version && show_menu
