#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"
INSTALL_DIR="/opt/ip-ban-hammer"
CONFIG_DIR="/etc/ip-ban-hammer"
DATA_DIR="/var/lib/ip-ban-hammer"
LOG_DIR="/var/log/ip-ban-hammer"
BIN_LINK="/usr/local/bin/ipban"
COMPLETION_DIR="/etc/bash_completion.d"

SYS_LANG=""
UPGRADE_MODE=0
CONFIG_ACTION=""

declare -A LANG_TEXT
declare -a LANG_CODES
declare -a LANG_NAMES

while [ $# -gt 0 ]; do
    case "$1" in
        --lang|-l)
            SYS_LANG="$2"
            shift 2
            ;;
        --upgrade|-u)
            UPGRADE_MODE=1
            CONFIG_ACTION="merge"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --lang, -l <zh|en>  Set language (default: interactive)"
            echo "  --upgrade, -u       Upgrade mode"
            echo "  --help, -h          Show this help"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

detect_available_languages() {
    local i18n_dir="${SCRIPT_DIR}/config/i18n"
    [ ! -d "$i18n_dir" ] && i18n_dir="${CONFIG_DIR}/i18n"
    
    if [ ! -d "$i18n_dir" ]; then
        LANG_CODES=("zh")
        LANG_NAMES=("中文")
        return
    fi
    
    LANG_CODES=()
    LANG_NAMES=()
    
    for lang_file in "$i18n_dir"/*.lang; do
        [ ! -f "$lang_file" ] && continue
        
        local code=$(basename "$lang_file" .lang)
        local name=""
        
        name=$(grep "^lang\.name=" "$lang_file" 2>/dev/null | head -1 | cut -d'=' -f2)
        name="${name#"${name%%[![:space:]]*}"}"
        
        [ -z "$name" ] && name="$code"
        
        LANG_CODES+=("$code")
        LANG_NAMES+=("$name")
    done
    
    if [ ${#LANG_CODES[@]} -eq 0 ]; then
        LANG_CODES=("zh")
        LANG_NAMES=("中文")
    fi
}

show_language_menu() {
    echo "============================================================"
    echo "请选择安装语言 / Select installation language:"
    echo "============================================================"
    echo ""
    
    local i=1
    for name in "${LANG_NAMES[@]}"; do
        echo "  $i) $name"
        i=$((i + 1))
    done
    echo ""
    
    local total=${#LANG_CODES[@]}
    read -p "请选择 [1-$total]: " lang_choice
    
    if [[ "$lang_choice" =~ ^[0-9]+$ ]] && [ "$lang_choice" -ge 1 ] && [ "$lang_choice" -le "$total" ]; then
        local idx=$((lang_choice - 1))
        SYS_LANG="${LANG_CODES[$idx]}"
    else
        SYS_LANG="${LANG_CODES[0]}"
    fi
}

load_lang() {
    local lang="$1"
    local file="${SCRIPT_DIR}/config/i18n/${lang}.lang"
    [ ! -f "$file" ] && file="${CONFIG_DIR}/i18n/${lang}.lang"
    [ ! -f "$file" ] && return
    
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        key="${key#"${key%%[![:space:]]*}"}"
        value="${value#"${value%%[![:space:]]*}"}"
        LANG_TEXT["$key"]="$value"
    done < "$file"
}

t() {
    echo "${LANG_TEXT[$1]:-$1}"
}

validate_cron() {
    local cron="$1"
    local count=$(echo "$cron" | awk '{print NF}')
    [ "$count" -ne 5 ] && return 1
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        ((octet < 0 || octet > 255)) && return 1
    done
    return 0
}

validate_ip_or_cidr() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            ((octet < 0 || octet > 255)) && return 1
        done
        return 0
    fi
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]+$ ]]; then
        local addr="${ip%/*}"
        local prefix="${ip#*/}"
        ((prefix < 0 || prefix > 32)) && return 1
        IFS='.' read -r -a octets <<< "$addr"
        for octet in "${octets[@]}"; do
            ((octet < 0 || octet > 255)) && return 1
        done
        return 0
    fi
    return 1
}

detect_log_files() {
    local -a found=()
    
    if [ -d "/www/wwwlogs" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] && found+=("$line")
        done < <(find /www/wwwlogs -maxdepth 1 -name "*.log" -type f ! -name "*.error.log" 2>/dev/null | sort -r | head -10)
    fi
    
    [ -f "/var/log/nginx/access.log" ] && found+=("/var/log/nginx/access.log")
    [ -f "/var/log/apache2/access.log" ] && found+=("/var/log/apache2/access.log")
    [ -f "/var/log/httpd/access_log" ] && found+=("/var/log/httpd/access_log")
    
    printf '%s\n' "${found[@]}" | sort -u
}

detect_local_ips() {
    local -a ips=()
    
    ips+=("127.0.0.1")
    
    local main_ip=$(ip route get 1 2>/dev/null | awk '{print $7; exit}')
    if [ -n "$main_ip" ] && [ "$main_ip" != "127.0.0.1" ]; then
        ips+=("$main_ip")
    fi
    
    local all_ips=$(hostname -I 2>/dev/null)
    for ip in $all_ips; do
        if [[ ! " ${ips[*]} " =~ " ${ip} " ]]; then
            ips+=("$ip")
        fi
    done
    
    printf '%s\n' "${ips[@]}"
}

get_public_ip() {
    local ip=""
    ip=$(curl -s --max-time 3 ifconfig.me 2>/dev/null) || \
    ip=$(curl -s --max-time 3 ip.sb 2>/dev/null) || \
    ip=$(curl -s --max-time 3 icanhazip.com 2>/dev/null)
    echo "$ip"
}

if [ -z "$SYS_LANG" ]; then
    detect_available_languages
    show_language_menu
fi

load_lang "$SYS_LANG"

echo ""
echo "============================================================"
if [ "$UPGRADE_MODE" -eq 1 ]; then
    echo "$(t 'install.upgrade_title')"
else
    echo "$(t 'install.title')"
fi
echo "============================================================"
echo ""

if [ -f "$CONFIG_DIR/security.conf" ] && [ -z "$CONFIG_ACTION" ]; then
    echo "$(t 'upgrade.detected')"
    echo "  1) $(t 'upgrade.option1')"
    echo "  2) $(t 'upgrade.option2')"
    echo "  3) $(t 'upgrade.option3')"
    echo ""
    read -p "$(t 'upgrade.select'): " choice
    
    case "$choice" in
        1) CONFIG_ACTION="overwrite" ;;
        2) CONFIG_ACTION="keep" ;;
        3|*) CONFIG_ACTION="merge" ;;
    esac
fi

echo "$(t 'install.step1')"
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$INSTALL_DIR/config/i18n"
mkdir -p "$INSTALL_DIR/lib/completion"
mkdir -p "$INSTALL_DIR/lib/ipban_core"
mkdir -p "$INSTALL_DIR/systemd"
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$DATA_DIR/config_backups"
mkdir -p "$LOG_DIR"
echo "  ✓ $INSTALL_DIR/"
echo "  ✓ $CONFIG_DIR/"
echo "  ✓ $DATA_DIR/"
echo "  ✓ $LOG_DIR/"

SELECTED_LOGS=""
if [ "$UPGRADE_MODE" -eq 0 ] && [ -z "$CONFIG_ACTION" ]; then
    echo ""
    echo "$(t 'install.step2')"
    echo ""
    echo "$(t 'log.detecting')"
    
    DETECTED_LOGS=$(detect_log_files)
    LOG_COUNT=$(echo "$DETECTED_LOGS" | grep -c . 2>/dev/null || echo 0)
    
    if [ "$LOG_COUNT" -gt 0 ]; then
        echo ""
        echo "$(t 'log.detected')"
        echo "$DETECTED_LOGS" | nl -w4 -s') ' | while read -r line; do
            local_file=$(echo "$line" | awk '{print $2}')
            if [ -f "$local_file" ]; then
                mtime=$(stat -c %y "$local_file" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
                size=$(du -h "$local_file" 2>/dev/null | cut -f1)
                printf "    %s\n" "$line ($(t 'log.modified'): $mtime, $(t 'log.size'): $size)"
            else
                printf "    %s\n" "$line"
            fi
        done
        echo ""
        
        while true; do
            read -p "$(t 'log.select'): " log_input
            
            if [ "$log_input" = "skip" ]; then
                SELECTED_LOGS="/var/log/nginx/access.log"
                break
            fi
            
            SELECTED_LOGS=""
            IFS=',' read -ra items <<< "$log_input"
            for item in "${items[@]}"; do
                item=$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                if [[ "$item" =~ ^[0-9]+$ ]]; then
                    path=$(echo "$DETECTED_LOGS" | sed -n "${item}p")
                    [ -n "$path" ] && SELECTED_LOGS="${SELECTED_LOGS}${path},"
                elif [[ "$item" =~ / ]]; then
                    SELECTED_LOGS="${SELECTED_LOGS}${item},"
                fi
            done
            SELECTED_LOGS=$(echo "$SELECTED_LOGS" | sed 's/,$//')
            
            if [ -n "$SELECTED_LOGS" ]; then
                break
            fi
            echo "$(t 'log.retry')"
        done
        
        echo ""
        echo "$(t 'log.selected')"
        echo "$SELECTED_LOGS" | tr ',' '\n' | while read -r log; do
            [ -n "$log" ] && echo "  - $log"
        done
        echo ""
        read -p "$(t 'log.confirm'): " confirm
        [[ ! "$confirm" =~ ^[Nn]$ ]] || { echo "$(t 'common.cancelled')"; exit 0; }
    else
        echo ""
        echo "$(t 'log.not_detected')"
        while true; do
            read -p "$(t 'log.manual'): " log_input
            [ -z "$log_input" ] && log_input="/var/log/nginx/access.log"
            SELECTED_LOGS="$log_input"
            break
        done
    fi
else
    if [ -f "$CONFIG_DIR/security.conf" ]; then
        SELECTED_LOGS=$(awk -F= "/^\[paths\]/{f=1} f&&/^log_files=/{print substr(\$0,index(\$0,\"=\")+1); exit}" "$CONFIG_DIR/security.conf" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    fi
    [ -z "$SELECTED_LOGS" ] && SELECTED_LOGS="/var/log/nginx/access.log"
fi

ALLOW_IPS=""
if [ "$UPGRADE_MODE" -eq 0 ] && [ -z "$CONFIG_ACTION" ]; then
    echo ""
    echo "$(t 'install.step3')"
    echo ""
    
    LOCAL_IPS=$(detect_local_ips)
    PUBLIC_IP=$(get_public_ip)
    
    echo "$(t 'ip.detected')"
    echo "  $(t 'ip.private')"
    for ip in $LOCAL_IPS; do
        [ "$ip" != "$PUBLIC_IP" ] && echo "    - $ip"
    done
    echo "  $(t 'ip.public')"
    if [ -n "$PUBLIC_IP" ]; then
        echo "    - $PUBLIC_IP"
    else
        echo "    - $(t 'ip.public_failed')"
    fi
    echo ""
    
    read -p "$(t 'ip.add_auto'): " add_auto
    if [[ ! "$add_auto" =~ ^[Nn]$ ]]; then
        for ip in $LOCAL_IPS; do
            ALLOW_IPS="${ALLOW_IPS}${ip}\n"
        done
        [ -n "$PUBLIC_IP" ] && ALLOW_IPS="${ALLOW_IPS}${PUBLIC_IP}\n"
    fi
    
    echo ""
    read -p "$(t 'ip.add_manual'): " manual_ips
    
    if [ -n "$manual_ips" ]; then
        IFS=',' read -ra ips <<< "$manual_ips"
        for ip in "${ips[@]}"; do
            ip=$(echo "$ip" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            if validate_ip_or_cidr "$ip"; then
                ALLOW_IPS="${ALLOW_IPS}${ip}\n"
            fi
        done
    fi
    
    ALLOW_IPS=$(echo -e "$ALLOW_IPS" | sort -u | grep -v '^$')
    
    echo ""
    echo "$(t 'ip.added')"
    echo "$ALLOW_IPS" | while read -r ip; do
        [ -n "$ip" ] && echo "  - $ip"
    done
else
    if [ -f "$CONFIG_DIR/allow.list" ]; then
        ALLOW_IPS=$(cat "$CONFIG_DIR/allow.list" | grep -v '^#' | grep -v '^$')
    fi
fi

ATTACK_THRESHOLD=5
TIME_WINDOW=30
if [ "$UPGRADE_MODE" -eq 0 ] && [ -z "$CONFIG_ACTION" ]; then
    echo ""
    echo "$(t 'install.step4')"
    echo ""
    echo "$(t 'policy.title')"
    echo "  1) $(t 'policy.option1')"
    echo "  2) $(t 'policy.option2')"
    echo "  3) $(t 'policy.option3')"
    echo "  4) $(t 'policy.option4')"
    echo "  5) $(t 'policy.option5')"
    echo ""
    
    read -p "$(t 'policy.select'): " policy_choice
    
    case "$policy_choice" in
        1) ATTACK_THRESHOLD=3; TIME_WINDOW=30 ;;
        2) ATTACK_THRESHOLD=5; TIME_WINDOW=30 ;;
        3) ATTACK_THRESHOLD=10; TIME_WINDOW=20 ;;
        4) ATTACK_THRESHOLD=15; TIME_WINDOW=10 ;;
        5)
            read -p "$(t 'policy.threshold_custom'): " ATTACK_THRESHOLD
            read -p "$(t 'policy.window_custom'): " TIME_WINDOW
            ATTACK_THRESHOLD=${ATTACK_THRESHOLD:-5}
            TIME_WINDOW=${TIME_WINDOW:-30}
            ;;
        *) ATTACK_THRESHOLD=5; TIME_WINDOW=30 ;;
    esac
    
    echo ""
    echo "$(t 'policy.selected')"
    echo "  - $(t 'policy.threshold'): $ATTACK_THRESHOLD $(t 'summary.times')"
    echo "  - $(t 'policy.window'): $TIME_WINDOW $(t 'summary.minutes')"
    echo "  - $(t 'policy.desc'): $(t 'policy.desc_format' | sed "s/{}/$TIME_WINDOW/;s/{}/$ATTACK_THRESHOLD/")"
    echo ""
    read -p "$(t 'common.confirm'): " confirm
else
    if [ -f "$CONFIG_DIR/security.conf" ]; then
        ATTACK_THRESHOLD=$(awk -F= "/^\[thresholds\]/{f=1} f&&/^attack_threshold=/{print substr(\$0,index(\$0,\"=\")+1); exit}" "$CONFIG_DIR/security.conf" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        TIME_WINDOW=$(awk -F= "/^\[thresholds\]/{f=1} f&&/^time_window_minutes=/{print substr(\$0,index(\$0,\"=\")+1); exit}" "$CONFIG_DIR/security.conf" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    fi
    ATTACK_THRESHOLD=${ATTACK_THRESHOLD:-5}
    TIME_WINDOW=${TIME_WINDOW:-30}
fi

CHAIN_NAME="IP_BAN_HAMMER"
DAYS_TO_KEEP=30
ANALYZE_CRON="*/30 * * * *"
CLEANUP_CRON="0 3 * * *"

if [ "$UPGRADE_MODE" -eq 0 ] && [ -z "$CONFIG_ACTION" ]; then
    echo ""
    echo "$(t 'install.step5')"
    echo ""
    
    read -p "$(t 'advanced.ask'): " advanced_choice
    
    if [[ "$advanced_choice" =~ ^[Yy]$ ]]; then
        echo ""
        read -p "$(t 'advanced.chain'): " chain_input
        [ -n "$chain_input" ] && CHAIN_NAME="$chain_input"
        
        read -p "$(t 'advanced.days'): " days_input
        [ -n "$days_input" ] && DAYS_TO_KEEP="$days_input"
        
        while true; do
            read -p "$(t 'advanced.analyze_cron'): " cron_input
            if [ -z "$cron_input" ] || validate_cron "$cron_input"; then
                [ -n "$cron_input" ] && ANALYZE_CRON="$cron_input"
                break
            fi
            echo "$(t 'advanced.cron_invalid')"
        done
        
        while true; do
            read -p "$(t 'advanced.cleanup_cron'): " cron_input
            if [ -z "$cron_input" ] || validate_cron "$cron_input"; then
                [ -n "$cron_input" ] && CLEANUP_CRON="$cron_input"
                break
            fi
            echo "$(t 'advanced.cron_invalid')"
        done
        
        echo ""
        echo "$(t 'advanced.done')"
        echo "  - $(t 'advanced.chain_label'): $CHAIN_NAME"
        echo "  - $(t 'advanced.history_days'): $DAYS_TO_KEEP $(t 'summary.days')"
        echo "  - $(t 'advanced.analyze_freq'): $ANALYZE_CRON"
        echo "  - $(t 'advanced.cleanup_time'): $CLEANUP_CRON"
    fi
else
    if [ -f "$CONFIG_DIR/security.conf" ]; then
        CHAIN_NAME=$(awk -F= "/^\[iptables\]/{f=1} f&&/^chain_name=/{print substr(\$0,index(\$0,\"=\")+1); exit}" "$CONFIG_DIR/security.conf" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        DAYS_TO_KEEP=$(awk -F= "/^\[thresholds\]/{f=1} f&&/^days_to_keep=/{print substr(\$0,index(\$0,\"=\")+1); exit}" "$CONFIG_DIR/security.conf" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        ANALYZE_CRON=$(awk -F= "/^\[cron\]/{f=1} f&&/^analyze_cron=/{print substr(\$0,index(\$0,\"=\")+1); exit}" "$CONFIG_DIR/security.conf" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        CLEANUP_CRON=$(awk -F= "/^\[cron\]/{f=1} f&&/^cleanup_cron=/{print substr(\$0,index(\$0,\"=\")+1); exit}" "$CONFIG_DIR/security.conf" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    fi
    CHAIN_NAME=${CHAIN_NAME:-IP_BAN_HAMMER}
    DAYS_TO_KEEP=${DAYS_TO_KEEP:-30}
    ANALYZE_CRON=${ANALYZE_CRON:-"*/30 * * * *"}
    CLEANUP_CRON=${CLEANUP_CRON:-"0 3 * * *"}
fi

echo ""
echo "$(t 'install.step6')"
cp "$SCRIPT_DIR/bin/auto_ban_attacks.py" "$INSTALL_DIR/bin/"
cp "$SCRIPT_DIR/bin/full_scan.py" "$INSTALL_DIR/bin/"
cp "$SCRIPT_DIR/bin/apply_iptables_ban.sh" "$INSTALL_DIR/bin/"
cp "$SCRIPT_DIR/bin/ban_manager.sh" "$INSTALL_DIR/bin/"
cp "$SCRIPT_DIR/bin/uninstall.sh" "$INSTALL_DIR/bin/"
chmod +x "$INSTALL_DIR/bin"/*.sh
chmod +x "$INSTALL_DIR/bin"/*.py
echo "  ✓ auto_ban_attacks.py"
echo "  ✓ full_scan.py"
echo "  ✓ apply_iptables_ban.sh"
echo "  ✓ ban_manager.sh"
echo "  ✓ uninstall.sh"

if [ -d "$SCRIPT_DIR/lib/ipban_core" ]; then
    cp "$SCRIPT_DIR/lib/ipban_core/"*.py "$INSTALL_DIR/lib/ipban_core/"
    echo "  ✓ lib/ipban_core/"
fi

if [ -d "$SCRIPT_DIR/systemd" ]; then
    cp "$SCRIPT_DIR/systemd/"*.service "$SCRIPT_DIR/systemd/"*.timer "$INSTALL_DIR/systemd/" 2>/dev/null
    echo "  ✓ systemd/"
fi

if [ -f "$SCRIPT_DIR/config/security.conf.example" ]; then
    cp "$SCRIPT_DIR/config/security.conf.example" "$INSTALL_DIR/config/"
    echo "  ✓ security.conf.example"
fi

if [ -f "$SCRIPT_DIR/config/allow.list.example" ]; then
    cp "$SCRIPT_DIR/config/allow.list.example" "$INSTALL_DIR/config/"
    echo "  ✓ allow.list.example"
fi

echo ""
echo "$(t 'install.step7')"

generate_security_conf() {
    cat > "$CONFIG_DIR/security.conf" << EOF
# IP Ban Hammer Configuration File
# Generated during installation, can be modified manually

[paths]
log_files = $SELECTED_LOGS
pending = /var/lib/ip-ban-hammer/pending.list
applied = /var/lib/ip-ban-hammer/applied.list
allow = /etc/ip-ban-hammer/allow.list
main_log = /var/log/ip-ban-hammer/main.log
history = /var/log/ip-ban-hammer/history.log
stats = /var/log/ip-ban-hammer/stats.log

[iptables]
chain_name = $CHAIN_NAME

[thresholds]
attack_threshold = $ATTACK_THRESHOLD
time_window_minutes = $TIME_WINDOW
days_to_keep = $DAYS_TO_KEEP
reverse_read_threshold_mb = 100

[cron]
analyze_cron = $ANALYZE_CRON
apply_cron = * * * * *
cleanup_cron = $CLEANUP_CRON

[general]
language = $SYS_LANG
color_output = true

[security]
skip_private_ip = true

# Log IP extraction: auto, first, forwarded, json, custom
log_ip_position = auto
# json_ip_key = remote_addr
# custom_ip_regex =

[alert]
# webhook_url = 
# email_to = 
EOF
}

if [ -n "$CONFIG_ACTION" ]; then
    case "$CONFIG_ACTION" in
        overwrite)
            generate_security_conf
            echo "  security.conf: $(t 'upgrade.overwritten')"
            ;;
        keep)
            echo "  security.conf: $(t 'upgrade.kept')"
            ;;
        merge)
            if [ -f "$CONFIG_DIR/security.conf" ]; then
                cp "$CONFIG_DIR/security.conf" "$CONFIG_DIR/security.conf.bak"
                echo "  $(t 'upgrade.backed_up'): $CONFIG_DIR/security.conf.bak"
            fi
            generate_security_conf
            echo "  security.conf: $(t 'upgrade.merged')"
            ;;
    esac
else
    if [ -f "$CONFIG_DIR/security.conf" ]; then
        cp "$CONFIG_DIR/security.conf" "$CONFIG_DIR/security.conf.bak"
        echo "  $(t 'upgrade.backed_up'): $CONFIG_DIR/security.conf.bak"
    fi
    generate_security_conf
    echo "  ✓ security.conf"
fi

if [ -n "$ALLOW_IPS" ]; then
    echo "# IP Ban Hammer Allow List" > "$CONFIG_DIR/allow.list"
    echo "# Generated during installation" >> "$CONFIG_DIR/allow.list"
    echo "" >> "$CONFIG_DIR/allow.list"
    echo "$ALLOW_IPS" >> "$CONFIG_DIR/allow.list"
    echo "  ✓ allow.list"
elif [ ! -f "$CONFIG_DIR/allow.list" ]; then
    touch "$CONFIG_DIR/allow.list"
    echo "  ✓ allow.list"
else
    echo "  allow.list $(t 'common.exists_skip')"
fi

mkdir -p "$CONFIG_DIR/i18n"
if [ -f "$SCRIPT_DIR/config/i18n/${SYS_LANG}.lang" ]; then
    cp "$SCRIPT_DIR/config/i18n/${SYS_LANG}.lang" "$CONFIG_DIR/i18n/"
    echo "  ✓ i18n/${SYS_LANG}.lang"
fi

touch "$DATA_DIR/pending.list"
touch "$DATA_DIR/applied.list"
touch "$LOG_DIR/main.log"
touch "$LOG_DIR/history.log"
touch "$LOG_DIR/stats.log"
echo "  ✓ pending.list"
echo "  ✓ applied.list"
echo "  ✓ main.log"
echo "  ✓ history.log"
echo "  ✓ stats.log"

echo ""
echo "$(t 'install.step8')"
chmod 600 "$CONFIG_DIR"/* 2>/dev/null || true
chmod 600 "$DATA_DIR"/* 2>/dev/null || true
chmod 600 "$LOG_DIR"/* 2>/dev/null || true
echo "  ✓ $CONFIG_DIR/ (600)"
echo "  ✓ $DATA_DIR/ (600)"
echo "  ✓ $LOG_DIR/ (600)"

echo ""
echo "$(t 'install.step9')"

SCHEDULER="cron"
if command -v systemctl >/dev/null 2>&1 && [ -d "/etc/systemd/system" ]; then
    echo ""
    echo "  $(t 'install.systemd_detected')"
    echo "  1$(t 'install.systemd_cron')"
    echo "  2$(t 'install.systemd_option')"
    echo ""
    read -p "  $(t 'install.systemd_select') " scheduler_choice
    case "$scheduler_choice" in
        2) SCHEDULER="systemd" ;;
        *) SCHEDULER="cron" ;;
    esac
fi

if [ "$SCHEDULER" = "systemd" ]; then
    echo "  $(t 'install.systemd_setup')"
    
    SYSTEMD_DIR="$INSTALL_DIR/systemd"
    if [ -d "$SYSTEMD_DIR" ]; then
        for service_file in "$SYSTEMD_DIR"/*.service "$SYSTEMD_DIR"/*.timer; do
            if [ -f "$service_file" ]; then
                cp "$service_file" /etc/systemd/system/
                echo "  ✓ $(basename $service_file)"
            fi
        done
        
        systemctl daemon-reload
        systemctl enable ipban-analyze.timer
        systemctl enable ipban-apply.timer
        systemctl enable ipban-cleanup.timer
        systemctl start ipban-analyze.timer
        systemctl start ipban-apply.timer
        systemctl start ipban-cleanup.timer
        
        echo "  ✓ $(t 'install.systemd_done')"
    else
        echo "  $(t 'install.systemd_fallback')"
        SCHEDULER="cron"
    fi
fi

if [ "$SCHEDULER" = "cron" ]; then
    CRON_D_FILE="/etc/cron.d/ip-ban-hammer"

if [ ! -d "/etc/cron.d" ]; then
    echo "  $(t 'install.cron_not_found')"
    CRON_FILE=$(mktemp /tmp/ip_ban_hammer_cron.XXXXXX)
    trap 'rm -f "$CRON_FILE"' EXIT INT TERM
    crontab -l > "$CRON_FILE" 2>/dev/null || true
    
    if ! grep -q "ip-ban-hammer" "$CRON_FILE" 2>/dev/null; then
        echo "" >> "$CRON_FILE"
        echo "# IP Ban Hammer" >> "$CRON_FILE"
        echo "$ANALYZE_CRON /usr/bin/python3 $INSTALL_DIR/bin/auto_ban_attacks.py >> $LOG_DIR/main.log 2>&1" >> "$CRON_FILE"
        echo "* * * * * $INSTALL_DIR/bin/apply_iptables_ban.sh >> $LOG_DIR/main.log 2>&1" >> "$CRON_FILE"
        echo "$CLEANUP_CRON $INSTALL_DIR/bin/ban_manager.sh cleanup >> $LOG_DIR/main.log 2>&1" >> "$CRON_FILE"
        crontab "$CRON_FILE"
        echo "  $(t 'common.cron_added') (user crontab)"
    else
        echo "  $(t 'common.exists_skip')"
    fi
    rm -f "$CRON_FILE"
else
    cat > "$CRON_D_FILE" << EOF
# IP Ban Hammer - Auto IP Ban System
# DO NOT EDIT THIS FILE MANUALLY
# Analyze logs
$ANALYZE_CRON root /usr/bin/python3 $INSTALL_DIR/bin/auto_ban_attacks.py >> $LOG_DIR/main.log 2>&1
# Apply bans
* * * * * root $INSTALL_DIR/bin/apply_iptables_ban.sh >> $LOG_DIR/main.log 2>&1
# Cleanup history
$CLEANUP_CRON root $INSTALL_DIR/bin/ban_manager.sh cleanup >> $LOG_DIR/main.log 2>&1
EOF
    chmod 600 "$CRON_D_FILE"
    echo "  ✓ /etc/cron.d/ip-ban-hammer"
fi
fi

echo ""
echo "$(t 'install.step10')"
ln -sf "$INSTALL_DIR/bin/ban_manager.sh" "$BIN_LINK"
echo "  $(t 'common.link_created'): $BIN_LINK"

if [ -d "$COMPLETION_DIR" ]; then
    if [ -f "$INSTALL_DIR/lib/completion/ipban.bash" ]; then
        cp "$INSTALL_DIR/lib/completion/ipban.bash" "$COMPLETION_DIR/ipban"
        echo "  $(t 'common.completion_installed')"
    else
        echo "  $(t 'common.completion_skip')"
    fi
else
    echo "  $(t 'common.completion_skip')"
fi

echo ""
echo "============================================================"
if [ "$UPGRADE_MODE" -eq 1 ] || [ -n "$CONFIG_ACTION" ]; then
    echo "$(t 'install.upgrade_done')"
else
    echo "$(t 'install.done')"
fi
echo "============================================================"
echo ""
echo "$(t 'summary.title')"
echo "  ──────────────────────────────────────────────────────────"
echo "  $(t 'summary.logs')"
echo "$SELECTED_LOGS" | tr ',' '\n' | while read -r log; do
    [ -n "$log" ] && echo "    - $log"
done
echo ""
echo "  $(t 'summary.whitelist')"
if [ -n "$ALLOW_IPS" ]; then
    echo "$ALLOW_IPS" | while read -r ip; do
        [ -n "$ip" ] && echo "    - $ip"
    done
else
    echo "    - $(t 'ip.none')"
fi
echo ""
echo "  $(t 'summary.policy')"
echo "    - $(t 'policy.threshold'): $ATTACK_THRESHOLD $(t 'summary.times')"
echo "    - $(t 'policy.window'): $TIME_WINDOW $(t 'summary.minutes')"
echo ""
echo "  $(t 'summary.advanced')"
echo "    - $(t 'advanced.chain_label'): $CHAIN_NAME"
echo "    - $(t 'advanced.history_days'): $DAYS_TO_KEEP $(t 'summary.days')"
echo "    - $(t 'advanced.analyze_freq'): $ANALYZE_CRON"
echo ""
echo "  $(t 'summary.language'): $SYS_LANG"
echo "  ──────────────────────────────────────────────────────────"
echo ""
echo "$(t 'manage.title')"
echo "  ipban status        # $(t 'manage.status')"
echo "  ipban config        # $(t 'manage.config')"
echo "  ipban --help        # $(t 'manage.help')"
echo ""
echo "$(t 'uninstall.section_title')"
echo "  $INSTALL_DIR/bin/uninstall.sh"
echo ""
echo "============================================================"