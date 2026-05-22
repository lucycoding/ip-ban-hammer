#!/bin/bash

export PATH="$PATH:/sbin:/usr/sbin"

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
INSTALL_DIR="/opt/ip-ban-hammer"
CONFIG_DIR="/etc/ip-ban-hammer"
DATA_DIR="/var/lib/ip-ban-hammer"
LOG_DIR="/var/log/ip-ban-hammer"
BIN_LINK="/usr/local/bin/ipban"
COMPLETION_FILE="/etc/bash_completion.d/ipban"

declare -A LANG_TEXT

if [ -f "/etc/ip-ban-hammer/security.conf" ]; then
    CONFIG_FILE="/etc/ip-ban-hammer/security.conf"
else
    CONFIG_FILE="${ROOT_DIR}/config/security.conf"
fi

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

SYS_LANG=$(get_config "general" "language" "zh")
load_lang "$SYS_LANG"

echo "$(t 'uninstall.title')"
echo ""
echo "$(t 'uninstall.warn')"
echo ""
read -p "$(t 'uninstall.confirm')" confirm

if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "$(t 'uninstall.cancelled')"
    exit 0
fi

echo ""
echo "$(t 'uninstall.removing')"

if [ -f "$CONFIG_DIR/security.conf" ]; then
    CHAIN_NAME=$(awk -F= "/^\[iptables\]/{f=1} f&&/^chain_name=/{print substr(\$0,index(\$0,\"=\")+1); exit}" "$CONFIG_DIR/security.conf" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
else
    CHAIN_NAME="IP_BAN_HAMMER"
fi

echo "  $(t 'uninstall.remove_chain'): $CHAIN_NAME"
if iptables -n -L "$CHAIN_NAME" > /dev/null 2>&1; then
    iptables -F "$CHAIN_NAME"
    if iptables -n -L INPUT 2>/dev/null | grep -q "$CHAIN_NAME"; then
        iptables -D INPUT -j "$CHAIN_NAME"
    fi
    iptables -X "$CHAIN_NAME"
fi

echo "  $(t 'uninstall.remove_cron')"

if [ -f "/etc/cron.d/ip-ban-hammer" ]; then
    rm -f "/etc/cron.d/ip-ban-hammer"
fi

CRON_FILE=$(mktemp /tmp/cron_backup.XXXXXX)
CRON_NEW=$(mktemp /tmp/cron_backup_new.XXXXXX)
trap 'rm -f "$CRON_FILE" "$CRON_NEW"' EXIT INT TERM
crontab -l > "$CRON_FILE" 2>/dev/null || true
if grep -q "ip-ban-hammer" "$CRON_FILE" 2>/dev/null; then
    grep -v "ip-ban-hammer" "$CRON_FILE" | grep -v "auto_ban_attacks.py" | grep -v "apply_iptables_ban.sh" | grep -v "ban_manager.sh" > "$CRON_NEW"
    crontab "$CRON_NEW"
fi
rm -f "$CRON_FILE" "$CRON_NEW"

echo "  $(t 'uninstall.remove_link')"
rm -f "$BIN_LINK"
rm -f "$COMPLETION_FILE"

echo "  $(t 'uninstall.remove_files')"
rm -rf "$INSTALL_DIR"

echo ""
echo "$(t 'uninstall.done')"
echo ""
echo "$(t 'uninstall.preserved')"
echo "  - $(t 'uninstall.keep_config') $CONFIG_DIR, $DATA_DIR"
echo "  - $(t 'uninstall.keep_data') $DATA_DIR"
echo "  - $(t 'uninstall.keep_logs') $LOG_DIR"
