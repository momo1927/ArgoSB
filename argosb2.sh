#!/bin/bash  # 改为bash解释器以支持更多特性
export LANG=en_US.UTF-8

# 增加错误处理函数
error_exit() {
    echo "$1" 1>&2
    exit 1
}
# 检查命令是否存在
check_dependency() {
    if ! command -v "$1" >/dev/null 2>&1; then
        error_exit "错误：缺少必要工具 $1，请先安装"
    fi
}

# 检查必要依赖
check_dependency curl
check_dependency grep
check_dependency awk
check_dependency sed
check_dependency base64

# 协议变量检查（移到更前面，避免逻辑混淆）
if ! find /proc/*/exe -type l 2>/dev/null | grep -E '/proc/[0-9]+/exe' | xargs -r readlink 2>/dev/null | grep -Eq 'agsb/(s|x)' && ! pgrep -f 'agsb/(s|x)' >/dev/null 2>&1; then
    [ -z "${vlpt+x}" ] || vlp=yes
    [ -z "${vmpt+x}" ] || { vmp=yes; vmag=yes; } 
    [ -z "${hypt+x}" ] || hyp=yes
    [ -z "${tupt+x}" ] || tup=yes
    [ -z "${xhpt+x}" ] || xhp=yes
    [ -z "${anpt+x}" ] || anp=yes
    # 修复条件判断的语法，使用明确的逻辑组合
    if ! { [ "$vlp" = yes ] || [ "$vmp" = yes ] || [ "$hyp" = yes ] || [ "$tup" = yes ] || [ "$xhp" = yes ] || [ "$anp" = yes ]; }; then
        echo "提示：使用此脚本时，请在脚本前至少设置一个协议变量哦，再见！"
        exit 1
    fi
fi

export uuid=${uuid:-'f7636b36-11bd-4e72-ac6d-fef534968f33'}
export port_vl_re=${vlpt:-''}
export port_vm_ws=${vmpt:-''}
export port_hy2=${hypt:-''}
export port_tu=${tupt:-''}
export port_xh=${xhpt:-''}
export port_an=${anpt:-''}
export ym_vl_re=${reym:-''}
export argo=${argo:-''}
export ARGO_DOMAIN=${agn:-''}
export ARGO_AUTH=${agk:-''}
export ipsw=${ip:-''}

showmode(){
    echo "显示节点信息：agsb或者脚本 list"
    echo "双栈VPS显示IPv4节点配置：ip=4 agsb或者脚本 list"
    echo "双栈VPS显示IPv6节点配置：ip=6 agsb或者脚本 list"
    echo "卸载脚本：agsb或者脚本 del"
}

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "Blogger博客 ：kjgx668.blogspot.com"
echo "YouTube频道 ：www.youtube.com/@kejigongxiang"
echo "ArgoSB一键无交互极简脚本【Sing-box + Xray + Argo三内核合一】"
echo "当前版本：V25.7.4 (修复版，使用Xray官方安装脚本)"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

hostname=$(uname -a | awk '{print $2}')
op=$(cat /etc/redhat-release 2>/dev/null || cat /etc/os-release 2>/dev/null | grep -i pretty_name | cut -d \" -f2)
[ -z "$(systemd-detect-virt 2>/dev/null)" ] && vi=$(virt-what 2>/dev/null) || vi=$(systemd-detect-virt 2>/dev/null)
case $(uname -m) in
    aarch64) cpu=arm64;;
    x86_64) cpu=amd64;;
    *) echo "目前脚本不支持$(uname -m)架构" && exit 1
esac
mkdir -p "$HOME/agsb"

# 下载文件并验证的函数
download_and_verify() {
    local url=$1
    local output=$2
    local expected_type=$3

    echo "正在从 $url 下载文件..."
    if ! curl -Lo "$output" -# --retry 3 --retry-delay 2 "$url"; then
        error_exit "下载 $url 失败"
    fi

    # 检查文件类型是否符合预期
    if ! file "$output" | grep -q "$expected_type"; then
        rm -f "$output"
       error_exit "下载的文件 $output 不是有效的 $expected_type 文件"
    fi

    chmod +x "$output"
}

warpcheck(){
    wgcfv6=$(curl -s6m5 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    wgcfv4=$(curl -s4m5 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
}

insuuid(){
    if [ -z "$uuid" ]; then
        if [ -e "$HOME/agsb/sing-box" ]; then
            uuid=$("$HOME/agsb/sing-box" generate uuid)
        elif [ -e "$HOME/agsb/xray" ]; then
            uuid=$("$HOME/agsb/xray" uuid)
        else
            # 如果两个内核都没有，生成一个随机UUID
            uuid=$(cat /proc/sys/kernel/random/uuid)
        fi
    fi
    echo "$uuid" > "$HOME/agsb/uuid"
    echo "UUID密码：$uuid"
}

installxray(){
    echo
    echo "=========启用xray内核========="
    # 定义可能的Xray可执行文件路径
    possible_paths=(
        "$HOME/agsb/xray"
        "$HOME/agsb/bin/xray"
        "/usr/local/bin/xray"
        "/usr/bin/xray"
    )
    
    # 尝试找到已安装的Xray
    found_xray=""
    for path in "${possible_paths[@]}"; do
        if [ -e "$path" ] && [ -x "$path" ]; then
            found_xray="$path"
            break
        fi
    done
    
    # 如果未找到，进行安装
    if [ -z "$found_xray" ]; then
        echo "未找到已安装的Xray，开始安装..."
        
        # 确保安装目录存在
        mkdir -p "$HOME/agsb/bin"
        
        # 方案1：尝试官方脚本安装
        echo "尝试通过官方脚本安装Xray..."
        curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o "$HOME/agsb/install-xray.sh"
        chmod +x "$HOME/agsb/install-xray.sh"
        export PREFIX="$HOME/agsb"
        if "$HOME/agsb/install-xray.sh"; then
            echo "官方脚本安装成功"
            rm -f "$HOME/agsb/install-xray.sh"
        else
            echo "官方脚本安装失败，尝试手动安装..."
            rm -f "$HOME/agsb/install-xray.sh"
            
            # 方案2：手动下载安装
            arch=$(uname -m)
            case $arch in
                x86_64) xray_arch="amd64" ;;
                aarch64) xray_arch="arm64" ;;
                *) error_exit "不支持的系统架构: $arch" ;;
            esac
            
            # 获取最新版本
            latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
            if [ -z "$latest_version" ]; then
                latest_version="v25.8.3"  #  fallback到已知版本
                echo "无法获取最新版本，使用默认版本: $latest_version"
            fi
            
            xray_url="https://github.com/XTLS/Xray-core/releases/download/$latest_version/Xray-linux-$xray_arch.zip"
            echo "手动下载Xray $latest_version ($xray_arch)..."
            
            if curl -L "$xray_url" -o "$HOME/agsb/xray.zip"; then
                # 解压并安装
                if command -v unzip >/dev/null 2>&1; then
                    unzip -q -o "$HOME/agsb/xray.zip" -d "$HOME/agsb/bin/"
                    rm -f "$HOME/agsb/xray.zip"
                    chmod +x "$HOME/agsb/bin/xray"
                else
                    error_exit "缺少unzip工具，无法解压安装包"
                fi
            else
                error_exit "无法下载Xray安装包，请检查网络连接"
            fi
        fi
        unset PREFIX
        
        # 再次检查是否安装成功
        for path in "${possible_paths[@]}"; do
            if [ -e "$path" ] && [ -x "$path" ]; then
                found_xray="$path"
                break
            fi
        done
    fi
    
    # 创建符号链接（如果需要）
    if [ -n "$found_xray" ] && [ ! -e "$HOME/agsb/xray" ]; then
        ln -s "$found_xray" "$HOME/agsb/xray"
        found_xray="$HOME/agsb/xray"
    fi
    
    # 最终检查
    if [ -z "$found_xray" ] || [ ! -x "$found_xray" ]; then
        # 最后的努力：显示可能的安装路径供用户手动处理
        echo "Xray安装路径检测："
        for path in "${possible_paths[@]}"; do
            if [ -e "$path" ]; then
                echo "找到文件但不可执行: $path"
                ls -l "$path"
            fi
        done
        error_exit "未找到Xray可执行文件，请手动安装"
    fi
    
    # 验证运行状态
    if ! "$found_xray" version >"$HOME/agsb/xray-version.log" 2>"$HOME/agsb/xray-error.log"; then
        echo "Xray运行错误详情："
        cat "$HOME/agsb/xray-error.log"
        error_exit "Xray已找到但无法运行"
    fi
    
    sbcore=$("$found_xray" version 2>/dev/null | awk '/^Xray/{print $2}')
    echo "已确认Xray可执行文件：$found_xray (版本: $sbcore)"
    
    # 生成配置文件
    cat > "$HOME/agsb/xr.json" <<EOF
{
  "log": {
    "access": "$HOME/agsb/xray-access.log",
    "error": "$HOME/agsb/xray-error.log",
    "loglevel": "warning"
  },
  "inbounds": [
EOF
    insuuid
    if [ -n "$xhp" ] || [ -n "$vlp" ]; then
        if [ -z "$ym_vl_re" ]; then
            ym_vl_re=www.yahoo.com
        fi
        echo "$ym_vl_re" > "$HOME/agsb/ym_vl_re"
        echo "Reality域名：$ym_vl_re"
        mkdir -p "$HOME/agsb/xrk"
        if [ ! -e "$HOME/agsb/xrk/private_key" ]; then
            key_pair=$("$found_xray" x25519)
            private_key=$(echo "$key_pair" | head -1 | awk '{print $3}')
            public_key=$(echo "$key_pair" | tail -n 1 | awk '{print $3}')
            short_id=$(date +%s%N | sha256sum | cut -c 1-8)
            echo "$private_key" > "$HOME/agsb/xrk/private_key"
            echo "$public_key" > "$HOME/agsb/xrk/public_key"
            echo "$short_id" > "$HOME/agsb/xrk/short_id"
        fi
        private_key_x=$(cat "$HOME/agsb/xrk/private_key")
        public_key_x=$(cat "$HOME/agsb/xrk/public_key")
        short_id_x=$(cat "$HOME/agsb/xrk/short_id")
    fi
    if [ -n "$xhp" ]; then
        xhp=xhpt
        if [ -z "$port_xh" ]; then
            port_xh=$(shuf -i 10000-65535 -n 1)
        fi
        echo "$port_xh" > "$HOME/agsb/port_xh"
        echo "Vless-xhttp-reality端口：$port_xh"
        cat >> "$HOME/agsb/xr.json" <<EOF
    {
      "tag":"xhttp-reality",
      "listen": "::",
      "port": ${port_xh},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "fingerprint": "chrome",
          "target": "${ym_vl_re}:443",
          "serverNames": [
            "${ym_vl_re}"
          ],
          "privateKey": "$private_key_x",
          "shortIds": ["$short_id_x"]
        },
        "xhttpSettings": {
          "host": "",
          "path": "${uuid}-xh",
          "mode": "auto"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "metadataOnly": false
      }
    }
EOF
    else
        xhp=xhptargo
    fi
    if [ -n "$xhp" ] && [ -n "$vlp" ]; then
        echo "," >> "$HOME/agsb/xr.json"
    fi
    if [ -n "$vlp" ]; then
        vlp=vlpt
        if [ -z "$port_vl_re" ]; then
            port_vl_re=$(shuf -i 10000-65535 -n 1)
        fi
        echo "$port_vl_re" > "$HOME/agsb/port_vl_re"
        echo "Vless-reality-vision端口：$port_vl_re"
        cat >> "$HOME/agsb/xr.json" <<EOF
        {
            "tag":"reality-vision",
            "listen": "::",
            "port": $port_vl_re,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "fingerprint": "chrome",
                    "dest": "${ym_vl_re}:443",
                    "serverNames": [
                      "${ym_vl_re}"
                    ],
                    "privateKey": "$private_key_x",
                    "shortIds": ["$short_id_x"]
                }
            },
          "sniffing": {
          "enabled": true,
          "destOverride": ["http", "tls", "quic"],
          "metadataOnly": false
          }
        }
EOF
    else
        vlp=vlptargo
    fi
    cat >> "$HOME/agsb/xr.json" <<EOF
  ]
}
EOF

    # 启动前检查
    echo "启动Xray前进行检查..."
    
    # 1. 检查配置文件语法
    echo "验证Xray配置文件..."
    if ! "$found_xray" test -c "$HOME/agsb/xr.json"; then
        echo "配置文件错误详情："
        "$found_xray" test -c "$HOME/agsb/xr.json" 2>&1
        error_exit "Xray配置文件存在语法错误，启动失败"
    fi
    
    # 2. 检查端口占用
    check_port_usage() {
        local port=$1
        if command -v lsof >/dev/null 2>&1; then
            if lsof -i :"$port" >/dev/null 2>&1; then
                echo "端口 $port 已被占用，尝试终止占用进程..."
                lsof -ti :"$port" | xargs -r kill -9
                sleep 2
                if lsof -i :"$port" >/dev/null 2>&1; then
                    error_exit "端口 $port 仍被占用，无法启动Xray"
                fi
            fi
        elif command -v netstat >/dev/null 2>&1; then
            if netstat -tulpn | grep -q ":$port"; then
                echo "端口 $port 已被占用"
                error_exit "端口 $port 已被占用，无法启动Xray"
            fi
        fi
    }
    
    # 检查配置中使用的端口
    if [ -n "$port_xh" ]; then
        check_port_usage "$port_xh"
    fi
    if [ -n "$port_vl_re" ]; then
        check_port_usage "$port_vl_re"
    fi
    
    # 3. 确保日志目录可写
    touch "$HOME/agsb/xray-access.log" "$HOME/agsb/xray-error.log"
    chmod 666 "$HOME/agsb/xray-access.log" "$HOME/agsb/xray-error.log"
    
    # 4. 停止已运行的Xray进程
    if pgrep -f "$found_xray" >/dev/null 2>&1; then
        echo "停止已运行的Xray进程..."
        pkill -f "$found_xray"
        sleep 2
    fi
    
    # 启动Xray并捕获错误
    echo "启动Xray服务..."
    if ! nohup "$found_xray" run -c "$HOME/agsb/xr.json" >"$HOME/agsb/xray-nohup.log" 2>&1 &; then
        echo "Xray启动命令执行失败，错误日志："
        cat "$HOME/agsb/xray-nohup.log"
        error_exit "Xray服务启动失败"
    fi
    
    # 验证启动状态
    sleep 3
    if pgrep -f "$found_xray" >/dev/null 2>&1; then
        echo "Xray服务启动成功，进程ID：$(pgrep -f "$found_xray")"
    else
        echo "Xray启动后意外退出，错误日志："
        cat "$HOME/agsb/xray-error.log"
        cat "$HOME/agsb/xray-nohup.log"
        error_exit "Xray服务启动失败"
    fi
}


installsb(){
    echo
    echo "=========启用Sing-box内核========="
    if [ ! -e "$HOME/agsb/sing-box" ]; then
        # 更新Sing-box下载链接
        case $cpu in
            amd64) sb_url="https://github.com/SagerNet/sing-box/releases/download/v1.12.4/sing-box_1.12.4_linux_x86_64-$(uname -s | tr '[:upper:]' '[:lower:]')-amd64" ;;
            arm64) sb_url="https://github.com/SagerNet/sing-box/releases/download/v1.12.4/sing-box_1.12.4_linux_x86_64-$(uname -s | tr '[:upper:]' '[:lower:]')-arm64" ;;
            *) error_exit "不支持的CPU架构: $cpu" ;;
        esac
        
        download_and_verify "$sb_url" "$HOME/agsb/sing-box" "ELF 64-bit executable"
        
        # 验证Sing-box是否可运行
        if ! "$HOME/agsb/sing-box" version >/dev/null 2>&1; then
            error_exit "Sing-box内核无法运行，请检查系统兼容性"
        fi
        
        sbcore=$("$HOME/agsb/sing-box" version 2>/dev/null | awk '/version/{print $NF}')
        echo "已安装Sing-box正式版内核：$sbcore"
    fi
    cat > "$HOME/agsb/sb.json" <<EOF
{
"log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
EOF
    insuuid
    command -v openssl >/dev/null 2>&1 && openssl ecparam -genkey -name prime256v1 -out "$HOME/agsb/private.key" >/dev/null 2>&1
    command -v openssl >/dev/null 2>&1 && openssl req -new -x509 -days 36500 -key "$HOME/agsb/private.key" -out "$HOME/agsb/cert.pem" -subj "/CN=www.bing.com" >/dev/null 2>&1
    if [ ! -f "$HOME/agsb/private.key" ]; then
        curl -Lso "$HOME/agsb/private.key" https://github.com/zzzhhh1/ArgoSB/releases/download/argosbx/private.key
        curl -Lso "$HOME/agsb/cert.pem" https://github.com/zzzhhh1/ArgoSB/releases/download/argosbx/cert.pem
    fi
    if [ -n "$hyp" ]; then
        hyp=hypt
        if [ -z "$port_hy2" ]; then
            port_hy2=$(shuf -i 10000-65535 -n 1)
        fi
        echo "$port_hy2" > "$HOME/agsb/port_hy2"
        echo "Hysteria-2端口：$port_hy2"
        cat >> "$HOME/agsb/sb.json" <<EOF
    {
        "type": "hysteria2",
        "tag": "hy2-sb",
        "listen": "::",
        "listen_port": ${port_hy2},
        "users": [
            {
                "password": "${uuid}"
            }
        ],
        "ignore_client_bandwidth":false,
        "tls": {
            "enabled": true,
            "alpn": [
                "h3"
            ],
            "certificate_path": "$HOME/agsb/cert.pem",
            "key_path": "$HOME/agsb/private.key"
        }
    },
EOF
    else
        hyp=hyptargo
    fi
    if [ -n "$tup" ]; then
        tup=tupt
        if [ -z "$port_tu" ]; then
            port_tu=$(shuf -i 10000-65535 -n 1)
        fi
        echo "$port_tu" > "$HOME/agsb/port_tu"
        echo "Tuic端口：$port_tu"
        cat >> "$HOME/agsb/sb.json" <<EOF
        {
            "type":"tuic",
            "tag": "tuic5-sb",
            "listen": "::",
            "listen_port": ${port_tu},
            "users": [
                {
                    "uuid": "${uuid}",
                    "password": "${uuid}"
                }
            ],
            "congestion_control": "bbr",
            "tls":{
                "enabled": true,
                "alpn": [
                    "h3"
                ],
                "certificate_path": "$HOME/agsb/cert.pem",
                "key_path": "$HOME/agsb/private.key"
            }
        },
EOF
    else
        tup=tuptargo
    fi
    if [ -n "$anp" ]; then
        anp=anpt
        if [ -z "$port_an" ]; then
            port_an=$(shuf -i 10000-65535 -n 1)
        fi
        echo "$port_an" > "$HOME/agsb/port_an"
        echo "Anytls端口：$port_an"
        cat >> "$HOME/agsb/sb.json" <<EOF
        {
            "type":"anytls",
            "tag":"anytls-sb",
            "listen":"::",
            "listen_port":${port_an},
            "users":[
                {
                  "password":"${uuid}"
                }
            ],
            "padding_scheme":[],
            "tls":{
                "enabled": true,
                "certificate_path": "$HOME/agsb/cert.pem",
                "key_path": "$HOME/agsb/private.key"
            }
        },
EOF
    else
        anp=anptargo
    fi
}

xrsbvm(){
    if [ -n "$vmp" ]; then
        vmp=vmpt
        if [ -z "$port_vm_ws" ]; then
            port_vm_ws=$(shuf -i 10000-65535 -n 1)
        fi
        echo "$port_vm_ws" > "$HOME/agsb/port_vm_ws"
        echo "Vmess-ws端口：$port_vm_ws"
        if [ -e "$HOME/agsb/xray" ]; then
            cat >> "$HOME/agsb/xr.json" <<EOF
        {
            "tag": "vmess-xr",
            "listen": "::",
            "port": ${port_vm_ws},
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                  "path": "${uuid}-vm"
            }
        },
            "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls", "quic"],
            "metadataOnly": false
            }
         }, 
EOF
        else
            cat >> "$HOME/agsb/sb.json" <<EOF
{
        "type": "vmess",
        "tag": "vmess-sb",
        "listen": "::",
        "listen_port": ${port_vm_ws},
        "users": [
            {
                "uuid": "${uuid}",
                "alterId": 0
            }
        ],
        "transport": {
            "type": "ws",
            "path": "${uuid}-vm",
            "max_early_data":2048,
            "early_data_header_name": "Sec-WebSocket-Protocol"
        }
    },
EOF
        fi
    else
        vmp=vmptargo
    fi
}

xrsbout(){
    # 修复Xray启动部分的语法错误
    if [ -e "$HOME/agsb/xray" ]; then
        sed -i '${s/,\s*$//}' "$HOME/agsb/xr.json"
        cat >> "$HOME/agsb/xr.json" <<EOF
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF
        echo "启动Xray服务..."
        # 修复语法错误：正确的后台启动方式
        if ! nohup "$HOME/agsb/xray" run -c "$HOME/agsb/xr.json" >/dev/null 2>&1 & then
            error_exit "Xray服务启动失败"
        fi
        # 检查Xray是否成功启动
        sleep 2
        if ! pgrep -f "$HOME/agsb/xray" >/dev/null 2>&1; then
            error_exit "Xray服务启动后意外退出，请检查日志"
        fi
    fi

    # 修复Sing-box启动部分的语法错误
    if [ -e "$HOME/agsb/sing-box" ]; then
        sed -i '${s/,\s*$//}' "$HOME/agsb/sb.json"
        cat >> "$HOME/agsb/sb.json" <<EOF
],
"outbounds": [
{
"type":"direct",
"tag":"direct"
}
]
}
EOF
        echo "启动Sing-box服务..."
        # 修复语法错误：正确的后台启动方式
        if ! nohup "$HOME/agsb/sing-box" run -c "$HOME/agsb/sb.json" >/dev/null 2>&1 & then
            error_exit "Sing-box服务启动失败"
        fi
        # 检查Sing-box是否成功启动
        sleep 2
        if ! pgrep -f "$HOME/agsb/sing-box" >/dev/null 2>&1; then
            error_exit "Sing-box服务启动后意外退出，请检查日志"
        fi
    fi
}

ins(){
    if [ "$hyp" != yes ] && [ "$tup" != yes ] && [ "$anp" != yes ]; then
        installxray
        xrsbvm
        xrsbout
        hyp="hyptargo"; tup="tuptargo"; anp="anptargo"
    elif [ "$xhp" != yes ] && [ "$vlp" != yes ]; then
        installsb
        xrsbvm
        xrsbout
        xhp="xhptargo"; vlp="vlptargo"
    else
        installsb
        installxray
        xrsbvm
        xrsbout
    fi
    if [ -n "$argo" ] && [ -n "$vmag" ]; then
        echo
        echo "=========启用Cloudflared-argo内核========="
        if [ ! -e "$HOME/agsb/cloudflared" ]; then
            argocore=$(curl -Ls https://data.jsdelivr.com/v1/package/gh/cloudflare/cloudflared | grep -Eo '"[0-9.]+"' | sed -n 1p | tr -d '",')
            echo "下载Cloudflared-argo最新正式版内核：$argocore"

            # 更新Cloudflared下载链接
            case $cpu in
                amd64) cloudflared_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64" ;;
                arm64) cloudflared_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64" ;;
                *) error_exit "不支持的CPU架构: $cpu" ;;
            esac

            download_and_verify "$cloudflared_url" "$HOME/agsb/cloudflared" "ELF 64-bit executable"

            # 验证Cloudflared是否可运行
            if ! "$HOME/agsb/cloudflared" version >/dev/null 2>&1; then
                error_exit "Cloudflared无法运行，请检查系统兼容性"
            fi
        fi
        if [ -n "${ARGO_DOMAIN}" ] && [ -n "${ARGO_AUTH}" ]; then
            name='固定'
            echo "启动固定Argo隧道..."
            # 修复启动命令语法
            if ! nohup "$HOME/agsb/cloudflared" tunnel --no-autoupdate --edge-ip-version auto --protocol http2 run --token "${ARGO_AUTH}" >/dev/null 2>&1 & then
                error_exit "固定Argo隧道启动失败"
            fi
            echo "${ARGO_DOMAIN}" > "$HOME/agsb/sbargoym.log"
            echo "${ARGO_AUTH}" > "$HOME/agsb/sbargotoken.log"
        else
            name='临时'
            echo "启动临时Argo隧道..."
            # 修复启动命令语法
            if ! nohup "$HOME/agsb/cloudflared" tunnel --url http://localhost:"${port_vm_ws}" --edge-ip-version auto --no-autoupdate --protocol http2 > "$HOME/agsb/argo.log" 2>&1 & then
                error_exit "临时Argo隧道启动失败"
            fi
        fi
        echo "申请Argo$name隧道中……请稍等"
        sleep 8
        if [ -n "${ARGO_DOMAIN}" ] && [ -n "${ARGO_AUTH}" ]; then
            argodomain=$(cat "$HOME/agsb/sbargoym.log" 2>/dev/null)
        else
            argodomain=$(grep -a trycloudflare.com "$HOME/agsb/argo.log" 2>/dev/null | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
        fi
        if [ -n "${argodomain}" ]; then
            echo "Argo$name隧道申请成功，域名为：$argodomain"
        else
            echo "Argo$name隧道申请失败，请稍后再试"
        fi
    fi
    echo
    # 修复条件判断的语法
    if find /proc/*/exe -type l 2>/dev/null | grep -E '/proc/[0-9]+/exe' | xargs -r readlink 2>/dev/null | grep -Eq 'agsb/(s|x)' || pgrep -f 'agsb/(s|x)' >/dev/null 2>&1; then
        [ -f ~/.bashrc ] || touch ~/.bashrc
        sed -i '/momo/d' ~/.bashrc
        echo "if ! find /proc/*/exe -type l 2>/dev/null | grep -E '/proc/[0-9]+/exe' | xargs -r readlink 2>/dev/null | grep -Eq 'agsb/(s|x)' && ! pgrep -f 'agsb/(s|x)' >/dev/null 2>&1; then export ip=\"${ipsw}\" argo=\"${argo}\" uuid=\"${uuid}\" $xhp=\"${port_xh}\" $anp=\"${port_an}\" $vlp=\"${port_vl_re}\" $vmp=\"${port_vm_ws}\" $hyp=\"${port_hy2}\" $tup=\"${port_tu}\" reym=\"${ym_vl_re}\" agn=\"${ARGO_DOMAIN}\" agk=\"${ARGO_AUTH}\"; bash <(curl -Ls https://raw.githubusercontent.com/yonggekkk/argosb/main/argosb.sh); fi" >> ~/.bashrc
        COMMAND="agsb"
        SCRIPT_PATH="$HOME/bin/$COMMAND"
        mkdir -p "$HOME/bin"
        curl -Ls https://github.com/momo1927/ArgoSB/raw/refs/heads/main/argosb2.sh > "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
        sed -i '/export PATH="\$HOME\/bin:\$PATH"/d' ~/.bashrc
        echo 'export PATH="$HOME/bin:$PATH"' >> "$HOME/.bashrc"
        grep -qxF 'source ~/.bashrc' ~/.bash_profile 2>/dev/null || echo 'source ~/.bashrc' >> ~/.bash_profile
        . ~/.bashrc
        crontab -l > /tmp/crontab.tmp 2>/dev/null
        sed -i '/agsb\/sing-box/d' /tmp/crontab.tmp
        sed -i '/agsb\/xray/d' /tmp/crontab.tmp
        if find /proc/*/exe -type l 2>/dev/null | grep -E '/proc/[0-9]+/exe' | xargs -r readlink 2>/dev/null | grep -q 'agsb/s' || pgrep -f 'agsb/s' >/dev/null 2>&1; then
            echo '@reboot /bin/sh -c "nohup $HOME/agsb/sing-box run -c $HOME/agsb/sb.json >/dev/null 2>&1 &"' >> /tmp/crontab.tmp
        fi
        if find /proc/*/exe -type l 2>/dev/null | grep -E '/proc/[0-9]+/exe' | xargs -r readlink 2>/dev/null | grep -q 'agsb/x' || pgrep -f 'agsb/x' >/dev/null 2>&1; then
            echo '@reboot /bin/sh -c "nohup $HOME/agsb/xray run -c $HOME/agsb/xr.json >/dev/null 2>&1 &"' >> /tmp/crontab.tmp
        fi
        sed -i '/agsb\/cloudflared/d' /tmp/crontab.tmp
        if [ -n "$argo" ] && [ -n "$vmag" ]; then
            if [ -n "${ARGO_DOMAIN}" ] && [ -n "${ARGO_AUTH}" ]; then
                echo '@reboot /bin/sh -c "nohup $HOME/agsb/cloudflared tunnel --no-autoupdate --edge-ip-version auto --protocol http2 run --token $(cat $HOME/agsb/sbargotoken.log 2>/dev/null) >/dev/null 2>&1 &"' >> /tmp/crontab.tmp
            else
                if [ -e "$HOME/agsb/xray" ]; then
                    echo '@reboot /bin/sh -c "nohup $HOME/agsb/cloudflared tunnel --url http://localhost:$(grep -A2 vmess-xr $HOME/agsb/xr.json | tail -1 | tr -cd 0-9) --edge-ip-version auto --no-autoupdate --protocol http2 > $HOME/agsb/argo.log 2>&1 &"' >> /tmp/crontab.tmp
                else
                    echo '@reboot /bin/sh -c "nohup $HOME/agsb/cloudflared tunnel --url http://localhost:$(grep -A2 vmess-sb $HOME/agsb/sb.json | tail -1 | tr -cd 0-9) --edge-ip-version auto --no-autoupdate --protocol http2 > $HOME/agsb/argo.log 2>&1 &"' >> /tmp/crontab.tmp
                fi
            fi
        fi
        crontab /tmp/crontab.tmp 2>/dev/null
        rm /tmp/crontab.tmp
        echo "ArgoSB脚本进程启动成功，安装完毕" && sleep 2
    else
        echo "ArgoSB脚本进程未启动，安装失败" && exit 1
    fi
}

cip(){
    ipbest(){
        serip=$(curl -s4m5 icanhazip.com -k || curl -s6m5 icanhazip.com -k)
        if echo "$serip" | grep -q ':'; then
            server_ip="[$serip]"
            echo "$server_ip" > "$HOME/agsb/server_ip.log"
        else
            server_ip="$serip"
            echo "$server_ip" > "$HOME/agsb/server_ip.log"
        fi
    }
    ipchange(){
        v4=$(curl -s4m5 icanhazip.com -k)
        v6=$(curl -s6m5 icanhazip.com -k)
        if [ -z "$v4" ]; then
            vps_ipv4='无IPV4'
            vps_ipv6="$v6"
        elif [ -n "$v4" ] && [ -n "$v6" ]; then
            vps_ipv4="$v4"
            vps_ipv6="$v6"
        else
            vps_ipv4="$v4"
            vps_ipv6='无IPV6'
        fi
        echo
        echo "=========当前服务器本地IP情况========="
        echo "本地IPV4地址：$vps_ipv4"
        echo "本地IPV6地址：$vps_ipv6"
        echo
        if [ "$ipsw" = "4" ]; then
            if [ -z "$v4" ]; then
                ipbest
            else
                server_ip="$v4"
                echo "$server_ip" > "$HOME/agsb/server_ip.log"
            fi
        elif [ "$ipsw" = "6" ]; then
            if [ -z "$v6" ]; then
                ipbest
            else
                server_ip="[$v6]"
                echo "$server_ip" > "$HOME/agsb/server_ip.log"
            fi
        else
            ipbest
        fi
    }
    warpcheck
    if ! echo "$wgcfv4" | grep -qE 'on|plus' && ! echo "$wgcfv6" | grep -qE 'on|plus'; then
        ipchange
    else
        systemctl stop wg-quick@wgcf >/dev/null 2>&1
        kill -15 $(pgrep warp-go) >/dev/null 2>&1 && sleep 2
        ipchange
        systemctl start wg-quick@wgcf >/dev/null 2>&1
        systemctl restart warp-go >/dev/null 2>&1
        systemctl enable warp-go >/dev/null 2>&1
        systemctl start warp-go >/dev/null 2>&1
    fi
    rm -rf "$HOME/agsb/jh.txt"
    uuid=$(cat "$HOME/agsb/uuid")
    server_ip=$(cat "$HOME/agsb/server_ip.log")
    echo "*********************************************************"
    echo "*********************************************************"
    echo "ArgoSB脚本输出节点配置如下："
    echo
    if [ -f "$HOME/agsb/port_xh" ] || [ -f "$HOME/agsb/port_vl_re" ]; then
        ym_vl_re=$(cat "$HOME/agsb/ym_vl_re")
        private_key_x=$(cat "$HOME/agsb/xrk/private_key")
        public_key_x=$(cat "$HOME/agsb/xrk/public_key")
        short_id_x=$(cat "$HOME/agsb/xrk/short_id")
    fi
    if [ -f "$HOME/agsb/port_xh" ]; then
        echo "【 vless-xhttp-reality 】节点信息如下："
        port_xh=$(cat "$HOME/agsb/port_xh")
        vl_xh_link="vless://$uuid@$server_ip:$port_xh?encryption=none&security=reality&sni=$ym_vl_re&fp=chrome&pbk=$public_key_x&sid=$short_id_x&type=xhttp&path=$uuid-xh&mode=auto#vl-xhttp-reality-$hostname"
        echo "$vl_xh_link" >> "$HOME/agsb/jh.txt"
        echo "$vl_xh_link"
        echo
    fi
    if [ -f "$HOME/agsb/port_vl_re" ]; then
        echo "【 vless-reality-vision 】节点信息如下："
        port_vl_re=$(cat "$HOME/agsb/port_vl_re")
        vl_link="vless://$uuid@$server_ip:$port_vl_re?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$ym_vl_re&fp=chrome&pbk=$public_key_x&sid=$short_id_x&type=tcp&headerType=none#vl-reality-vision-$hostname"
        echo "$vl_link" >> "$HOME/agsb/jh.txt"
        echo "$vl_link"
        echo
    fi
    if [ -f "$HOME/agsb/port_vm_ws" ]; then
        echo "【 vmess-ws 】节点信息如下："
        port_vm_ws=$(cat "$HOME/agsb/port_vm_ws")
        vm_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vm-ws-$hostname\", \"add\": \"$server_ip\", \"port\": \"$port_vm_ws\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"www.bing.com\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
        echo "$vm_link" >> "$HOME/agsb/jh.txt"
        echo "$vm_link"
        echo
    fi
    if [ -f "$HOME/agsb/port_an" ]; then
        echo "【 AnyTLS 】节点信息如下："
        port_an=$(cat "$HOME/agsb/port_an")
        an_link="anytls://$uuid@$server_ip:$port_an?insecure=1#anytls-$hostname"
        echo "$an_link" >> "$HOME/agsb/jh.txt"
        echo "$an_link"
        echo
    fi
    if [ -f "$HOME/agsb/port_hy2" ]; then
        echo "【 Hysteria2 】节点信息如下："
        port_hy2=$(cat "$HOME/agsb/port_hy2")
        hy2_link="hysteria2://$uuid@$server_ip:$port_hy2?security=tls&alpn=h3&insecure=1&sni=www.bing.com#hy2-$hostname"
        echo "$hy2_link" >> "$HOME/agsb/jh.txt"
        echo "$hy2_link"
        echo
    fi
    if [ -f "$HOME/agsb/port_tu" ]; then
        echo "【 Tuic 】节点信息如下："
        port_tu=$(cat "$HOME/agsb/port_tu")
        tuic5_link="tuic://$uuid:$uuid@$server_ip:$port_tu?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=www.bing.com&allow_insecure=1#tu5-$hostname"
        echo "$tuic5_link" >> "$HOME/agsb/jh.txt"
        echo "$tuic5_link"
        echo
    fi
    argodomain=$(cat "$HOME/agsb/sbargoym.log" 2>/dev/null)
    [ -z "$argodomain" ] && argodomain=$(grep -a trycloudflare.com "$HOME/agsb/argo.log" 2>/dev/null | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
    if [ -n "$argodomain" ]; then
        vmatls_link1="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-tls-argo-$hostname-443\", \"add\": \"104.16.0.0\", \"port\": \"443\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
        echo "$vmatls_link1" >> "$HOME/agsb/jh.txt"
        vmatls_link2="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-tls-argo-$hostname-8443\", \"add\": \"104.17.0.0\", \"port\": \"8443\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
        echo "$vmatls_link2" >> "$HOME/agsb/jh.txt"
        vmatls_link3="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-tls-argo-$hostname-2053\", \"add\": \"104.18.0.0\", \"port\": \"2053\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
        echo "$vmatls_link3" >> "$HOME/agsb/jh.txt"
        vmatls_link4="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-tls-argo-$hostname-2083\", \"add\": \"104.19.0.0\", \"port\": \"2083\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
        echo "$vmatls_link4" >> "$HOME/agsb/jh.txt"
        vmatls_link5="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-tls-argo-$hostname-2087\", \"add\": \"104.20.0.0\", \"port\": \"2087\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
        echo "$vmatls_link5" >> "$HOME/agsb/jh.txt"
        vmatls_link6="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-tls-argo-$hostname-2096\", \"add\": \"[2606:4700::0]\", \"port\": \"2096\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
        echo "$vmatls_link6" >> "$HOME/agsb/jh.txt"
        vma_link7="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-argo-$hostname-80\", \"add\": \"104.21.0.0\", \"port\": \"80\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
        echo "$vma_link7" >> "$HOME/agsb/jh.txt"
        vma_link8="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-argo-$hostname-8080\", \"add\": \"104.22.0.0\", \"port\": \"8080\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
        echo "$vma_link8" >> "$HOME/agsb/jh.txt"
        vma_link9="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-argo-$hostname-8880\", \"add\": \"104.24.0.0\", \"port\": \"8880\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
        echo "$vma_link9" >> "$HOME/agsb/jh.txt"
        vma_link10="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-argo-$hostname-2052\", \"add\": \"104.25.0.0\", \"port\": \"2052\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
        echo "$vma_link10" >> "$HOME/agsb/jh.txt"
        vma_link11="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-argo-$hostname-2082\", \"add\": \"104.26.0.0\", \"port\": \"2082\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
        echo "$vma_link11" >> "$HOME/agsb/jh.txt"
        vma_link12="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-argo-$hostname-2086\", \"add\": \"104.27.0.0\", \"port\": \"2086\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
        echo "$vma_link12" >> "$HOME/agsb/jh.txt"
        vma_link13="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-argo-$hostname-2095\", \"add\": \"[2400:cb00:2049::0]\", \"port\": \"2095\", \"id\": \"$uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$uuid-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
        echo "$vma_link13" >> "$HOME/agsb/jh.txt"
        sbtk=$(cat "$HOME/agsb/sbargotoken.log" 2>/dev/null)
        if [ -n "$sbtk" ]; then
            nametn="当前Argo固定隧道token：$sbtk"
        fi
        argoshow=$(echo "Vmess主协议端口(Argo固定隧道端口)：$port_vm_ws\n当前Argo$name域名：$argodomain\n$nametn\n1、443端口的vmess-ws-tls-argo节点\n$vmatls_link1\n\n2、80端口的vmess-ws-argo节点\n$vma_link7\n")
    fi
    echo "---------------------------------------------------------"
    echo -e "$argoshow"
    echo "---------------------------------------------------------"
    echo "聚合节点信息，请查看$HOME/agsb/jh.txt文件或者运行cat $HOME/agsb/jh.txt进行复制"
    echo "---------------------------------------------------------"
    echo "相关快捷方式如下：(首次安装成功后需重连SSH，agsb快捷方式才可生效)"
    showmode
    echo "---------------------------------------------------------"
    echo
}

# 处理命令参数
if [ "$1" = "del" ]; then
    for P in /proc/[0-9]*; do 
        if [ -L "$P/exe" ]; then 
            TARGET=$(readlink -f "$P/exe" 2>/dev/null)
            if echo "$TARGET" | grep -qE '/agsb/c|/agsb/s|/agsb/x'; then 
                PID=$(basename "$P")
                kill "$PID" 2>/dev/null && echo "Killed $PID ($TARGET)" || echo "Could not kill $PID ($TARGET)"
            fi 
        fi 
    done
    kill -15 $(pgrep -f 'agsb/s' 2>/dev/null) $(pgrep -f 'agsb/c' 2>/dev/null) $(pgrep -f 'agsb/x' 2>/dev/null) >/dev/null 2>&1
    sed -i '/momo/d' ~/.bashrc
    sed -i '/export PATH="\$HOME\/bin:\$PATH"/d' ~/.bashrc
    . ~/.bashrc
    crontab -l > /tmp/crontab.tmp 2>/dev/null
    sed -i '/agsb\/sing-box/d' /tmp/crontab.tmp
    sed -i '/agsb\/xray/d' /tmp/crontab.tmp
    sed -i '/agsb\/cloudflared/d' /tmp/crontab.tmp
    crontab /tmp/crontab.tmp 2>/dev/null
    rm /tmp/crontab.tmp
    rm -rf "$HOME/agsb" "$HOME/bin/agsb"
    echo "卸载完成"
    exit 0
elif [ "$1" = "list" ]; then
    cip
    exit 0
fi

# 628行附近的核心条件判断（已修复）
if ! find /proc/*/exe -type l 2>/dev/null | grep -E '/proc/[0-9]+/exe' | xargs -r readlink 2>/dev/null | grep -Eq 'agsb/(s|x)' && ! pgrep -f 'agsb/(s|x)' >/dev/null 2>&1; then
    # 终止相关进程
    for P in /proc/[0-9]*; do 
        if [ -L "$P/exe" ]; then 
            TARGET=$(readlink -f "$P/exe" 2>/dev/null)
            if echo "$TARGET" | grep -qE '/agsb/c|/agsb/s|/agsb/x'; then 
                PID=$(basename "$P")
                kill "$PID" 2>/dev/null && echo "Killed $PID ($TARGET)" || echo "Could not kill $PID ($TARGET)"
            fi 
        fi 
    done
    kill -15 $(pgrep -f 'agsb/s' 2>/dev/null) $(pgrep -f 'agsb/c' 2>/dev/null) $(pgrep -f 'agsb/x' 2>/dev/null) >/dev/null 2>&1
    
    # 定义DNS配置函数
    v4orv6(){
        if [ -z "$(curl -s4m5 icanhazip.com -k)" ]; then
            echo -e "nameserver 2a00:1098:2b::1\nnameserver 2a00:1098:2c::1\nnameserver 2a01:4f8:c2c:123f::1" > /etc/resolv.conf
        fi
    }
    
    # 检查并配置Warp
    warpcheck
    if ! echo "$wgcfv4" | grep -qE 'on|plus' && ! echo "$wgcfv6" | grep -qE 'on|plus'; then
        v4orv6
    else
        systemctl stop wg-quick@wgcf >/dev/null 2>&1
        kill -15 $(pgrep warp-go) >/dev/null 2>&1 && sleep 2
        v4orv6
        systemctl start wg-quick@wgcf >/dev/null 2>&1
        systemctl restart warp-go >/dev/null 2>&1
        systemctl enable warp-go >/dev/null 2>&1
        systemctl start warp-go >/dev/null 2>&1
    fi
    
    # 开始安装流程
    echo "VPS系统：$op"
    echo "CPU架构：$cpu"
    echo "ArgoSB脚本未安装，开始安装…………" && sleep 2
    setenforce 0 >/dev/null 2>&1
    iptables -P INPUT ACCEPT >/dev/null 2>&1
    iptables -P FORWARD ACCEPT >/dev/null 2>&1
    iptables -P OUTPUT ACCEPT >/dev/null 2>&1
    iptables -F >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1
    ins
    cip
    echo
else
    # 628行附近的else（已修复匹配问题）
    echo "ArgoSB脚本已安装"
    echo "相关快捷方式如下："
    showmode
    exit 0
fi
