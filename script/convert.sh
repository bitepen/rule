#!/usr/bin/env bash
set -euo pipefail

# 始终从仓库根目录执行定位
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ts() { date +"%Y-%m-%d %H:%M:%S"; }

fix_cidr_in_file() {
    local file="$1"
    sed -i -E 's/^(IP-CIDR,([0-9]{1,3}(\.[0-9]{1,3}){3}))(,no-resolve)$/\1\/24\4/' "$file"
    sed -i -E 's/^(IP-CIDR6,([0-9a-fA-F:]+))(,no-resolve)$/\1\/128\3/' "$file"
}

download_and_check() {
    local output_file=$1
    local expected_md5=$2
    local url=$3
    local output_text_file=$4

    if wget -q --no-proxy -O "$output_file" "$url"; then
        local actual_md5
        actual_md5=$(md5sum "$output_file" | awk '{print $1}')
        if [[ "$actual_md5" == "$expected_md5" ]]; then
            rm -f "$output_file"
        else
            cp "$output_file" "$output_text_file"
        fi
    else
        echo "❌ 下载转换失败: $url" >&2
    fi
}

echo "[$(ts)] 开始: 检查发生变动的 Clash 规则文件"

# 抓取在 rule/Clash 目录下发生变动的所有 .list
mapfile -t CHANGED_FILES < <(git diff --name-only --diff-filter=ACMR HEAD -- "rule/Clash/**/*.list" 2>/dev/null || true)

if [ ${#CHANGED_FILES[@]} -eq 0 ]; then
    echo "💡 没有检测到 rule/Clash 目录下的变动文件，无需转换！"
    exit 0
fi

echo "共发现 ${#CHANGED_FILES[@]} 个 Clash 规则文件发生变动，开始处理..."

# 阶段 1: subconverter 拆分转换
for rel_path in "${CHANGED_FILES[@]}"; do
    [ -f "$rel_path" ] || continue
    fix_cidr_in_file "$rel_path"

    # Python 服务器根目录是 ./rule/，所以去掉前面的 rule/
    sub_path="${rel_path#rule/}"
    RAW_URL="http://127.0.0.1:8080/$sub_path"
    RAW_URL_BASE64=$(printf '%s' "$RAW_URL" | openssl base64 -A)

    base_no_ext="${rel_path%.list}"
    OUTPUT_FILE_DOMAIN_YAML="${base_no_ext}_OCD_Domain.yaml"
    OUTPUT_FILE_DOMAIN_TEXT="${base_no_ext}_OCD_Domain.txt"
    OUTPUT_FILE_IP_YAML="${base_no_ext}_OCD_IP.yaml"
    OUTPUT_FILE_IP_TEXT="${base_no_ext}_OCD_IP.txt"

    download_and_check "$OUTPUT_FILE_DOMAIN_YAML" \
        "0c04407cd072968894bd80a426572b13" \
        "http://127.0.0.1:25500/getruleset?type=3&url=$RAW_URL_BASE64" \
        "$OUTPUT_FILE_DOMAIN_TEXT"

    download_and_check "$OUTPUT_FILE_IP_YAML" \
        "3d6eaeec428ed84741b4045f4b85eee3" \
        "http://127.0.0.1:25500/getruleset?type=4&url=$RAW_URL_BASE64" \
        "$OUTPUT_FILE_IP_TEXT"
done

# 阶段 2: 编译为 .mrs
echo "[$(ts)] 开始: 针对更新的文件编译 .mrs"
for rel_path in "${CHANGED_FILES[@]}"; do
    base_no_ext="${rel_path%.list}"
    for txt_file in "${base_no_ext}_OCD_Domain.txt" "${base_no_ext}_OCD_IP.txt"; do
        [ -f "$txt_file" ] || continue

        if head -n1 "$txt_file" | grep -q "payload"; then
            sed -i '1d' "$txt_file"
        fi
        sed -i "s/^[[:space:]]*-[[:space:]]*//; s/'//g; s/[[:space:]]//g" "$txt_file"

        filename=$(basename "$txt_file" .txt)
        file_dir=$(dirname "$txt_file")

        case "$filename" in
            *_OCD_Domain*) param="domain" ;;
            *_OCD_IP*)     param="ipcidr" ;;
            *) continue ;;
        esac

        output_file="$file_dir/$filename.mrs"
        /usr/bin/mihomo convert-ruleset "$param" text "$txt_file" "$output_file"
        echo "✅ 成功生成二进制规则: $output_file"
    done
done

echo "[$(ts)] 转换流程全部完成！"