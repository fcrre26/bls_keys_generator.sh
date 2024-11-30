#!/bin/bash

VERSION="1.4.1"
CONFIG_FILE="/root/.eth_bls_config"

# 加载或创建默认配置
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        VENV_PATH="/root/.venv/eth_bls_env"
        OUTPUT_DIR="/root/.local/eth_bls_output"
        LOG_FILE="$OUTPUT_DIR/eth_bls_key_gen.log"
        MNEMONIC_FILE="$OUTPUT_DIR/0_mnemonics.txt"
        ETH_ADDRESSES_FILE="$OUTPUT_DIR/1_eth_addresses.txt"
        ETH_PRIVATE_KEYS_FILE="$OUTPUT_DIR/2_eth_private_keys.txt"
        ETH_PUBLIC_KEYS_FILE="$OUTPUT_DIR/3_eth_public_keys.txt"
        BLS_PRIVATE_KEYS_FILE="$OUTPUT_DIR/4_bls_private_keys.txt"
        BLS_PUBLIC_KEYS_FILE="$OUTPUT_DIR/5_bls_public_keys.txt"
        COMBINED_KEYS_FILE="$OUTPUT_DIR/6_combined_keys.txt"
        CSV_FILE="$OUTPUT_DIR/combined_keys.csv"

        mkdir -p "$(dirname "$CONFIG_FILE")"
        cat > "$CONFIG_FILE" <<EOL
VENV_PATH="$VENV_PATH"
OUTPUT_DIR="$OUTPUT_DIR"
LOG_FILE="$LOG_FILE"
MNEMONIC_FILE="$MNEMONIC_FILE"
ETH_ADDRESSES_FILE="$ETH_ADDRESSES_FILE"
ETH_PRIVATE_KEYS_FILE="$ETH_PRIVATE_KEYS_FILE"
ETH_PUBLIC_KEYS_FILE="$ETH_PUBLIC_KEYS_FILE"
BLS_PRIVATE_KEYS_FILE="$BLS_PRIVATE_KEYS_FILE"
BLS_PUBLIC_KEYS_FILE="$BLS_PUBLIC_KEYS_FILE"
COMBINED_KEYS_FILE="$COMBINED_KEYS_FILE"
CSV_FILE="$CSV_FILE"
EOL
    fi
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

handle_error() {
    log "错误: $1"
    exit 1
}

# 创建并激活虚拟环境
create_and_activate_venv() {
    if [[ ! -d "$VENV_PATH" ]]; then
        log "创建虚拟环境..."
        python3.10 -m venv "$VENV_PATH" || handle_error "虚拟环境创建失败"
    fi

    log "虚拟环境路径: $VENV_PATH"
    
    if [[ ! -f "$VENV_PATH/bin/activate" ]]; then
        handle_error "虚拟环境激活脚本未找到: $VENV_PATH/bin/activate"
    fi

    log "激活虚拟环境..."
    source "$VENV_PATH/bin/activate" || handle_error "无法激活虚拟环境，请检查路径是否正确: $VENV_PATH/bin/activate"
}

# 前置条件检查
ensure_prerequisites() {
    log "检查并安装所有生成密钥所需的前置条件..."
    mkdir -p /root/.local/eth_bls_output
    apt update || handle_error "系统更新失败"
    apt install -y software-properties-common || handle_error "安装软件属性包失败"
    add-apt-repository -y ppa:deadsnakes/ppa || handle_error "添加 PPA 失败"
    apt update || handle_error "更新包列表失败"
    apt install -y build-essential python3.10 python3.10-venv python3.10-dev python3-pip || handle_error "依赖安装失败"
    log "Python版本: $(python3.10 --version)"
    create_and_activate_venv
    pip install py_ecc==6.0.0 eth_keys==0.4.0 bip_utils==2.7.0 || handle_error "必要库安装失败"
    log "前置条件检查和安装已完成。您现在可以开始生成密钥。"
}

# 从助记词生成所有密钥
generate_all_keys_from_mnemonic() {
    local mnemonic="$1"
    local num_addresses="$2"
    local result
    result=$("$VENV_PATH/bin/python3.10" -c '
import sys
from py_ecc.bls import G2ProofOfPossession
from eth_keys import keys
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Changes, Bip44Coins
import secrets
import traceback

def int_to_hex(x):
    return hex(x)[2:].zfill(64)

try:
    mnemonic = "'"$mnemonic"'"
    num_addresses = '"$num_addresses"'
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    results = []

    for i in range(num_addresses):
        bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
        bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
        bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)
        eth_private_key_bytes = bip44_addr_ctx.PrivateKey().Raw().ToBytes()

        eth_key = keys.PrivateKey(eth_private_key_bytes)
        eth_public_key = eth_key.public_key
        eth_address = eth_key.public_key.to_checksum_address()
        bls_private_key = G2ProofOfPossession.KeyGen(secrets.token_bytes(32))
        bls_public_key = G2ProofOfPossession.SkToPk(bls_private_key)

        results.append(f"{eth_address}|0x{eth_private_key_bytes.hex()}|{eth_public_key.to_hex()}|0x{int_to_hex(bls_private_key)}|0x{bls_public_key.hex()}")

    print("\n".join(results))

except Exception as e:
    print(f"Error: {str(e)}", file=sys.stderr)
    print("Traceback:", file=sys.stderr)
    print(traceback.format_exc(), file=sys.stderr)
    sys.exit(1)
' 2>&1)
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        echo "$result" | grep -v "^Error:" | grep -v "^Traceback:"
    else
        return 1
    fi
}

# 验证助记词格式
validate_mnemonic() {
    local mnemonic="$1"
    local word_count=$(echo "$mnemonic" | wc -w)
    if [[ $word_count -ne 12 && $word_count -ne 15 && $word_count -ne 18 && $word_count -ne 21 && $word_count -ne 24 ]]; then
        return 1
    fi
    return 0
}

# 批量生成所有密钥（从助记词）
batch_generate_all_keys_from_mnemonic() {
    create_and_activate_venv
    log "开始批量生成所有密钥（从助记词）..."
    csv_file="$OUTPUT_DIR/combined_keys.csv"

    > "$MNEMONIC_FILE"
    > "$ETH_ADDRESSES_FILE"
    > "$ETH_PRIVATE_KEYS_FILE"
    > "$ETH_PUBLIC_KEYS_FILE"
    > "$BLS_PRIVATE_KEYS_FILE"
    > "$BLS_PUBLIC_KEYS_FILE"
    > "$COMBINED_KEYS_FILE"
    > "$csv_file"

    echo -e "\xEF\xBB\xBF序号,助记词,ETH地址,ETH私钥,ETH公钥,BLS私钥,BLS公钥" > "$csv_file"
    echo "序号 助记词 ETH地址 ETH私钥 ETH公钥 BLS私钥 BLS公钥" > "$COMBINED_KEYS_FILE"

    echo "请粘贴助记词（可以一次性粘贴多个，每行一个），然后按两次回车确认录入："
    temp_input_file=$(mktemp)

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -z "$line" ]]; then
            break
        fi
        echo "$line" >> "$temp_input_file"
    done

    read -p "请输入每个助记词要生成的地址数量: " num_addresses
    total_mnemonics=$(wc -l < "$temp_input_file")
    current_mnemonic=0

    while IFS= read -r mnemonic; do
        current_mnemonic=$((current_mnemonic + 1))
        log "处理第 $current_mnemonic / $total_mnemonics 个助记词"

        if ! validate_mnemonic "$mnemonic"; then
            log "警告: 无效的助记词格式: $mnemonic. 跳过此助记词。"
            continue
        fi

        echo "$mnemonic" >> "$MNEMONIC_FILE"
        result=$(generate_all_keys_from_mnemonic "$mnemonic" "$num_addresses")
        exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            valid_result=$(echo "$result" | grep -v "^Error:")
            if [[ -n "$valid_result" ]]; then
                index=0
                echo "$valid_result" | while IFS='|' read -r eth_address eth_private_key eth_pub bls_priv bls_pub; do
                    index=$((index + 1))
                    echo "$eth_address" >> "$ETH_ADDRESSES_FILE"
                    echo "$eth_private_key" >> "$ETH_PRIVATE_KEYS_FILE"
                    echo "$eth_pub" >> "$ETH_PUBLIC_KEYS_FILE"
                    echo "$bls_priv" >> "$BLS_PRIVATE_KEYS_FILE"
                    echo "$bls_pub" >> "$BLS_PUBLIC_KEYS_FILE"
                    echo "$current_mnemonic $mnemonic $eth_address $eth_private_key $eth_pub $bls_priv $bls_pub" >> "$COMBINED_KEYS_FILE"
                    echo "$current_mnemonic,$mnemonic,$eth_address,$eth_private_key,$eth_pub,$bls_priv,$bls_pub" >> "$csv_file"
                done
                log "成功生成所有密钥: 助记词: $mnemonic"
            else
                log "生成失败，未能解析有效结果"
            fi
        else
            log "生成失败，跳过助记词: $mnemonic"
        fi
        echo -ne "进度: $((current_mnemonic * 100 / total_mnemonics))%\r"
    done < "$temp_input_file"

    rm "$temp_input_file"
    log "所有密钥已保存至 $OUTPUT_DIR 目录下的相应文件中。"
}

# 从私钥生成所有密钥
generate_all_keys_from_private_key() {
    local private_key="$1"
    local result
    result=$("$VENV_PATH/bin/python3.10" -c '
import secrets
from eth_keys import keys
from py_ecc.bls import G2ProofOfPossession

def int_to_hex(x):
    return hex(x)[2:].zfill(64)

try:
    private_key = "'"$private_key"'"
    eth_key = keys.PrivateKey(bytes.fromhex(private_key[2:]))
    eth_address = eth_key.public_key.to_checksum_address()
    eth_pub = eth_key.public_key.to_hex()
    bls_private_key = G2ProofOfPossession.KeyGen(secrets.token_bytes(32))
    bls_public_key = G2ProofOfPossession.SkToPk(bls_private_key)

    bls_public_key_hex = "0x" + bls_public_key.hex()
    bls_priv_hex = "0x" + int_to_hex(bls_private_key)

    print(f"{private_key}|{eth_address}|{eth_pub}|{bls_priv_hex}|{bls_public_key_hex}")

except Exception as e:
    print(f"Error: {str(e)}")
' 2>&1)

    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        echo "$result" | grep -v "^Error:"
    else
        return 1
    fi
}

# 批量生成所有密钥（从私钥）
batch_generate_all_keys_from_private_key() {
    create_and_activate_venv
    log "开始批量生成所有密钥（从私钥）..."

    > "$ETH_ADDRESSES_FILE"
    > "$ETH_PRIVATE_KEYS_FILE"
    > "$ETH_PUBLIC_KEYS_FILE"
    > "$BLS_PRIVATE_KEYS_FILE"
    > "$BLS_PUBLIC_KEYS_FILE"
    > "$COMBINED_KEYS_FILE"
    > "$CSV_FILE"

    echo "请输入私钥（每行一个），然后按两次回车确认录入："
    temp_input_file=$(mktemp)

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -z "$line" ]]; then
            break
        fi
        echo "$line" >> "$temp_input_file"
    done

    echo -e "\xEF\xBB\xBFETH私钥,ETH地址,ETH公钥,BLS私钥,BLS公钥" > "$CSV_FILE"

    while IFS= read -r private_key; do
        result=$(generate_all_keys_from_private_key "$private_key")
        exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            log "生成成功: $result"
            echo "$result" | while IFS='|' read -r eth_priv_hex eth_address eth_pub bls_priv bls_pub; do
                echo "$eth_address" >> "$ETH_ADDRESSES_FILE"
                echo "$eth_priv_hex" >> "$ETH_PRIVATE_KEYS_FILE"
                echo "$eth_pub" >> "$ETH_PUBLIC_KEYS_FILE"
                echo "$bls_priv" >> "$BLS_PRIVATE_KEYS_FILE"
                echo "$bls_pub" >> "$BLS_PUBLIC_KEYS_FILE"
                echo "$eth_priv_hex $eth_address $eth_pub $bls_priv $bls_pub" >> "$COMBINED_KEYS_FILE"
                echo "$eth_priv_hex,$eth_address,$eth_pub,$bls_priv,$bls_pub" >> "$CSV_FILE"
            done
        else
            log "生成失败: $result"
        fi
    done < "$temp_input_file"

    rm "$temp_input_file"
    log "所有密钥已保存至 $OUTPUT_DIR 目录下的相应文件和 CSV 文件中。"
}

# 自动生成账户
auto_generate_accounts() {
    create_and_activate_venv
    log "开始自动生成账户..."
    read -p "请输入要生成的账户数量: " num_accounts

    > "$MNEMONIC_FILE"
    > "$ETH_ADDRESSES_FILE"
    > "$ETH_PRIVATE_KEYS_FILE"
    > "$ETH_PUBLIC_KEYS_FILE"
    > "$BLS_PRIVATE_KEYS_FILE"
    > "$BLS_PUBLIC_KEYS_FILE"
    > "$COMBINED_KEYS_FILE"
    > "$CSV_FILE"

    echo -e "\xEF\xBB\xBF助记词,ETH地址,ETH私钥,ETH公钥,BLS私钥,BLS公钥" > "$CSV_FILE"
    echo "助记词 ETH地址 ETH私钥 ETH公钥 BLS私钥 BLS公钥" > "$COMBINED_KEYS_FILE"

    for _ in $(seq 1 "$num_accounts"); do
        result=$("$VENV_PATH/bin/python3.10" -c '
import secrets
from eth_keys import keys
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from py_ecc.bls import G2ProofOfPossession

def int_to_hex(x):
    return hex(x)[2:].zfill(64)

try:
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(12)
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(0)

    eth_private_key_bytes = bip44_addr_ctx.PrivateKey().Raw().ToBytes()
    eth_key = keys.PrivateKey(eth_private_key_bytes)
    eth_public_key = eth_key.public_key
    eth_address = eth_key.public_key.to_checksum_address()

    bls_private_key = G2ProofOfPossession.KeyGen(secrets.token_bytes(32))
    bls_public_key = G2ProofOfPossession.SkToPk(bls_private_key)

    bls_public_key_hex = "0x" + bls_public_key.hex()
    bls_priv_hex = "0x" + int_to_hex(bls_private_key)
    eth_priv_hex = "0x" + eth_private_key_bytes.hex()
    eth_pub_hex = eth_public_key.to_hex()

    print(f"{mnemonic}|{eth_address}|{eth_priv_hex}|{eth_pub_hex}|{bls_priv_hex}|{bls_public_key_hex}")

except Exception as e:
    print(f"Error: {str(e)}")
' 2>&1)

        if [[ $? -eq 0 ]]; then
            log "生成成功: $result"
            echo "$result" | while IFS='|' read -r mnemonic eth_address eth_priv_hex eth_pub bls_priv bls_pub; do
                echo "$mnemonic" >> "$MNEMONIC_FILE"
                echo "$eth_address" >> "$ETH_ADDRESSES_FILE"
                echo "$eth_priv_hex" >> "$ETH_PRIVATE_KEYS_FILE"
                echo "$eth_pub" >> "$ETH_PUBLIC_KEYS_FILE"
                echo "$bls_priv" >> "$BLS_PRIVATE_KEYS_FILE"
                echo "$bls_pub" >> "$BLS_PUBLIC_KEYS_FILE"
                echo "$mnemonic $eth_address $eth_priv_hex $eth_pub $bls_priv $bls_pub" >> "$COMBINED_KEYS_FILE"
                echo "$mnemonic,$eth_address,$eth_priv_hex,$eth_pub,$bls_priv,$bls_pub" >> "$CSV_FILE"
            done
        else
            log "生成失败: $result"
        fi
    done

    log "所有生成的账户信息已保存至 $OUTPUT_DIR 目录下的相应文件和 CSV 文件中。"
}


# 主菜单选项列表
show_menu() {
    echo "欢迎使用以太坊和BLS密钥生成工具 (版本 $VERSION)"
    echo "1. 检查并安装所有生成密钥的前置条件"
    echo "2. 批量生成所有密钥（从助记词）"
    echo "3. 批量生成所有密钥（从私钥）"
    echo "4. 自动生成账户"
    echo "5. 移除脚本和所有相关文件"
    echo "6. 退出"
}

# 主循环
main_loop() {
    while true; do
        show_menu
        read -p "请输入选项 [1-6]: " option
        case $option in
            1) ensure_prerequisites ;;
            2) batch_generate_all_keys_from_mnemonic ;;
            3) batch_generate_all_keys_from_private_key ;;
            4) auto_generate_accounts ;;
            5) remove_script_and_files ;;
            6) echo "退出程序。"; exit 0 ;;
            *) echo "无效选项，请重新输入。" ;;
        esac
        echo ""  # 打印空行作为选项后的间隔
    done
}

# 启动脚本
load_config 
main_loop
