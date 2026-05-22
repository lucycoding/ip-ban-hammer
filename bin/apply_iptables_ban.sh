#!/bin/bash

export PATH="$PATH:/sbin:/usr/sbin"

DRY_RUN=false
if [ "$1" = "--dry-run" ] || [ "$1" = "-n" ]; then
    DRY_RUN=true
    shift
fi

SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SCRIPT_SOURCE" ]; do
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
    SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
    case "$SCRIPT_SOURCE" in
        /*) ;;
        *) SCRIPT_SOURCE="$SCRIPT_DIR/$SCRIPT_SOURCE" ;;
    esac
done
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

if [ -f "/etc/ip-ban-hammer/security.conf" ]; then
    CONFIG_FILE="/etc/ip-ban-hammer/security.conf"
else
    CONFIG_FILE="${ROOT_DIR}/config/security.conf"
fi

declare -A LANG_TEXT

load_lang() {
    local lang="$1"
    local file="/etc/ip-ban-hammer/i18n/${lang}.lang"
    [ ! -f "$file" ] && file="${ROOT_DIR}/config/i18n/${lang}.lang"
    [ ! -f "$file" ] && return
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        LANG_TEXT["$key"]="$value"
    done < "$file"
}

t() {
    echo "${LANG_TEXT[$1]:-$1}"
}

LOCK_FILE="/tmp/ip-ban-hammer-apply.lock"
LOCK_FD=200

acquire_lock() {
    if command -v flock >/dev/null 2>&1; then
        eval "exec $LOCK_FD>\"$LOCK_FILE\""
        if ! flock -n $LOCK_FD; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Another instance is running, exiting"
            exit 0
        fi
    fi
}

release_lock() {
    if command -v flock >/dev/null 2>&1; then
        flock -u $LOCK_FD 2>/dev/null
    fi
    rm -f "$LOCK_FILE" 2>/dev/null
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if ((octet < 0 || octet > 255)); then
            return 1
        fi
    done
    return 0
}

is_private_ip() {
    local ip="$1"
    local first second
    IFS='.' read -r first second _ <<< "$ip"
    
    [ "$first" = "0" ] && return 0
    [ "$first" = "10" ] && return 0
    [ "$first" = "172" ] && [ "$second" -ge 16 ] 2>/dev/null && [ "$second" -le 31 ] 2>/dev/null && return 0
    [ "$first" = "192" ] && [ "$second" = "168" ] && return 0
    [ "$first" = "127" ] && return 0
    [ "$first" = "169" ] && [ "$second" = "254" ] && return 0
    [ "$first" -ge 224 ] 2>/dev/null && [ "$first" -le 239 ] 2>/dev/null && return 0
    [ "$first" -ge 240 ] 2>/dev/null && [ "$first" -le 255 ] 2>/dev/null && return 0
    
    return 1
}

is_in_whitelist() {
    local ip="$1"
    local whitelist_file="$2"
    
    [[ ! -f "$whitelist_file" ]] && return 1
    
    if grep -qxF "$ip" "$whitelist_file" 2>/dev/null; then
        return 0
    fi
    
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$ip" "$whitelist_file" << 'PYEOF'
import ipaddress, sys
try:
    ip = ipaddress.ip_address(sys.argv[1])
    with open(sys.argv[2]) as f:
        for line in f:
            item = line.strip().split('#')[0].strip()
            if '/' in item:
                try:
                    if ip in ipaddress.ip_network(item, strict=False):
                        sys.exit(0)
                except ValueError:
                    pass
except ValueError:
    pass
sys.exit(1)
PYEOF
        return $?
    fi
    
    return 1
}

get_config() {
    local section="$1"
    local key="$2"
    local default="$3"
    
    if [ -f "$CONFIG_FILE" ]; then
        value=$(awk -F= "/^\[$section\]/{f=1} f&&/^$key=/{print substr(\$0,index(\$0,\"=\")+1); exit}" "$CONFIG_FILE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [ -n "$value" ]; then
            echo "$value"
        else
            echo "$default"
        fi
    else
        echo "$default"
    fi
}

SYS_LANG=$(get_config "general" "language" "zh")
load_lang "$SYS_LANG"

PENDING_FILE=$(get_config "paths" "pending" "/var/lib/ip-ban-hammer/pending.list")
APPLIED_FILE=$(get_config "paths" "applied" "/var/lib/ip-ban-hammer/applied.list")
IPTABLES_CHAIN=$(get_config "iptables" "chain_name" "IP_BAN_HAMMER")
HISTORY_FILE=$(get_config "paths" "history" "/var/log/ip-ban-hammer/history.log")
ALLOW_FILE=$(get_config "paths" "allow" "/etc/ip-ban-hammer/allow.list")
SKIP_PRIVATE_IP=$(get_config "security" "skip_private_ip" "true")

acquire_lock
trap release_lock EXIT INT TERM

if [ ! -f "$PENDING_FILE" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $(t 'apply.ban_list_not_exist'): $PENDING_FILE" >> "$HISTORY_FILE"
    exit 1
fi

if [ "$DRY_RUN" = "true" ]; then
    echo "$(t 'apply.dry_run_mode')"
    echo ""
fi

if ! iptables -n -L "$IPTABLES_CHAIN" > /dev/null 2>&1; then
    if [ "$DRY_RUN" = "true" ]; then
        printf "$(t 'apply.dry_run_chain')\n" "$IPTABLES_CHAIN"
        printf "$(t 'apply.dry_run_input')\n" "$IPTABLES_CHAIN"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') | $(t 'apply.create_chain'): $IPTABLES_CHAIN" >> "$HISTORY_FILE"
        iptables -N "$IPTABLES_CHAIN"
        iptables -I INPUT -j "$IPTABLES_CHAIN"
    fi
fi

if [ ! -f "$APPLIED_FILE" ]; then
    touch "$APPLIED_FILE"
fi

new_count=0
skip_count=0
whitelist_skip=0
private_skip=0

while IFS= read -r line; do
    ip=$(printf '%s\n' "$line" | grep -v '^#' | awk '{print $1}')
    
    if [ -z "$ip" ]; then
        continue
    fi
    
    if ! validate_ip "$ip"; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') | $(t 'apply.invalid_ip'): $ip" >> "$HISTORY_FILE"
        continue
    fi
    
    if [ "$SKIP_PRIVATE_IP" = "true" ] && is_private_ip "$ip"; then
        private_skip=$((private_skip + 1))
        continue
    fi
    
    if is_in_whitelist "$ip" "$ALLOW_FILE"; then
        whitelist_skip=$((whitelist_skip + 1))
        continue
    fi
    
    if grep -qxF "$ip" "$APPLIED_FILE" 2>/dev/null; then
        skip_count=$((skip_count + 1))
        continue
    fi
    
    if iptables -n -L "$IPTABLES_CHAIN" 2>/dev/null | grep -qw "$ip"; then
        echo "$ip" >> "$APPLIED_FILE"
        skip_count=$((skip_count + 1))
        continue
    fi
    
    if [ "$DRY_RUN" = "true" ]; then
        printf "$(t 'apply.dry_run_ban')\n" "$IPTABLES_CHAIN" "$ip"
        new_count=$((new_count + 1))
    else
        iptables -I "$IPTABLES_CHAIN" -s "$ip" -j DROP
        
        if [ $? -eq 0 ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') | $ip | applied | iptables" >> "$HISTORY_FILE"
            echo "$ip" >> "$APPLIED_FILE"
            new_count=$((new_count + 1))
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') | $(t 'apply.ban_failed'): $ip" >> "$HISTORY_FILE"
        fi
    fi
    
done < "$PENDING_FILE"

if [ "$DRY_RUN" = "true" ]; then
    echo ""
    printf "$(t 'apply.dry_run_summary')\n" "$new_count"
    printf "$(t 'apply.dry_run_skipped')\n" "$skip_count"
    printf "$(t 'apply.dry_run_wl')\n" "$whitelist_skip"
    printf "$(t 'apply.dry_run_private')\n" "$private_skip"
    exit 0
fi

total_banned=$(iptables -n -L "$IPTABLES_CHAIN" 2>/dev/null | grep -c DROP)

echo "$(date '+%Y-%m-%d %H:%M:%S') | $(printf "$(t 'apply.complete')" "$new_count" "$skip_count" "$total_banned")" >> "$HISTORY_FILE"

if [ $whitelist_skip -gt 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $(printf "$(t 'apply.skip_wl')" "$whitelist_skip")" >> "$HISTORY_FILE"
fi

if [ $private_skip -gt 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $(printf "$(t 'apply.skip_private')" "$private_skip")" >> "$HISTORY_FILE"
fi

if [ $new_count -gt 0 ]; then
    if [ -d /etc/iptables ] 2>/dev/null || mkdir -p /etc/iptables 2>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
    elif [ -d /etc/sysconfig ] 2>/dev/null || mkdir -p /etc/sysconfig 2>/dev/null; then
        iptables-save > /etc/sysconfig/iptables 2>/dev/null
    fi
fi

if [ -f "$PENDING_FILE" ]; then
    > "$PENDING_FILE"
fi
