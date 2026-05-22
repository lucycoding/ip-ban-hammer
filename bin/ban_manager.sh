#!/bin/bash

export PATH="$PATH:/sbin:/usr/sbin"

VERSION="1.0.0"

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

declare -A LANG_TEXT

if [ -f "/etc/ip-ban-hammer/security.conf" ]; then
    CONFIG_FILE="/etc/ip-ban-hammer/security.conf"
else
    CONFIG_FILE="${ROOT_DIR}/config/security.conf"
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

print_color() {
    local color="$1"
    shift
    printf "${color}%s${NC}\n" "$*"
}

print_success() { print_color "$GREEN" "$*"; }
print_error() { print_color "$RED" "$*"; }
print_warning() { print_color "$YELLOW" "$*"; }
print_info() { print_color "$CYAN" "$*"; }
print_header() { print_color "$BOLD$BLUE" "$*"; }

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

is_private_ip() {
    local ip="$1"
    local first second
    IFS='.' read -r first second _ <<< "$ip"
    
    [ "$first" = "0" ] && return 0
    [ "$first" = "10" ] && return 0
    
    if [ "$first" = "172" ]; then
        if [ "$second" -ge 16 ] 2>/dev/null && [ "$second" -le 31 ] 2>/dev/null; then
            return 0
        fi
    fi
    
    [ "$first" = "192" ] && [ "$second" = "168" ] && return 0
    [ "$first" = "127" ] && return 0
    [ "$first" = "169" ] && [ "$second" = "254" ] && return 0
    
    if [ "$first" -ge 224 ] 2>/dev/null && [ "$first" -le 239 ] 2>/dev/null; then
        return 0
    fi
    
    if [ "$first" -ge 240 ] 2>/dev/null && [ "$first" -le 255 ] 2>/dev/null; then
        return 0
    fi
    
    return 1
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "$(t 'error.need_root')"
        exit 1
    fi
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

escape_for_sed() {
    printf '%s\n' "$1" | sed 's/[.[\*^$()+?{|/]/\\&/g'
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
COLOR_OUTPUT=$(get_config "general" "color_output" "true")

if [ "$COLOR_OUTPUT" != "true" ]; then
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''; BOLD=''
fi

IPTABLES_CHAIN=$(get_config "iptables" "chain_name" "IP_BAN_HAMMER")
APPLIED_FILE=$(get_config "paths" "applied" "/var/lib/ip-ban-hammer/applied.list")
PENDING_FILE=$(get_config "paths" "pending" "/var/lib/ip-ban-hammer/pending.list")
HISTORY_FILE=$(get_config "paths" "history" "/var/log/ip-ban-hammer/history.log")
STATS_FILE=$(get_config "paths" "stats" "/var/log/ip-ban-hammer/stats.log")
ALLOW_FILE=$(get_config "paths" "allow" "/etc/ip-ban-hammer/allow.list")
DAYS_TO_KEEP=$(get_config "thresholds" "days_to_keep" "30")
MAIN_LOG=$(get_config "paths" "main_log" "/var/log/ip-ban-hammer/main.log")

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

load_lang "$SYS_LANG"

show_version() {
    echo ""
    print_header "$(t 'manager.title')"
    print_info "$(t 'manager.version'): $VERSION"
    echo ""
}

show_help() {
    show_version
    echo "$(t 'manager.usage'): ipban <command> [options]"
    echo ""
    printf "  %-18s %s\n" "status" "$(t 'manager.cmd_status')" 
    printf "  %-18s %s\n" "list" "$(t 'manager.cmd_list')" 
    printf "  %-18s %s\n" "ban <IP>" "$(t 'manager.cmd_ban')" 
    printf "  %-18s %s\n" "unban <IP>" "$(t 'manager.cmd_unban')" 
    printf "  %-18s %s\n" "flush" "$(t 'manager.cmd_flush')" 
    printf "  %-18s %s\n" "cleanup [days]" "$(t 'manager.cmd_cleanup')" 
    printf "  %-18s %s\n" "whitelist" "$(t 'manager.cmd_whitelist')" 
    printf "  %-18s %s\n" "whitelist add <IP>" "$(t 'manager.cmd_wl_add')" 
    printf "  %-18s %s\n" "whitelist del <IP>" "$(t 'manager.cmd_wl_del')" 
    printf "  %-18s %s\n" "analyze [--full|--days N]" "$(t 'manager.cmd_analyze')" 
    printf "  %-18s %s\n" "analyze --preview" "$(t 'help.preview_mode')" 
    printf "  %-18s %s\n" "stats" "$(t 'manager.cmd_stats')" 
    printf "  %-18s %s\n" "logs [N]" "$(t 'manager.cmd_logs')" 
    printf "  %-18s %s\n" "check" "$(t 'manager.cmd_check')" 
    printf "  %-18s %s\n" "config" "$(t 'manager.cmd_config')" 
    printf "  %-18s %s\n" "config get <section.key>" "$(t 'config.cmd_get')"
    printf "  %-18s %s\n" "config set <section.key> <value>" "$(t 'config.cmd_set')"
    printf "  %-18s %s\n" "config edit" "$(t 'config.cmd_edit')"
    printf "  %-18s %s\n" "config backup" "$(t 'config.cmd_backup')"
    printf "  %-18s %s\n" "config backups" "$(t 'config.cmd_backups')"
    printf "  %-18s %s\n" "config restore <backup>" "$(t 'config.cmd_restore')"
    printf "  %-18s %s\n" "version" "$(t 'manager.cmd_version')" 
    printf "  %-18s %s\n" "help [command]" "$(t 'manager.cmd_help')" 
    echo ""
    echo "$(t 'manager.config'): $CONFIG_FILE"
}

show_help_command() {
    local cmd="$1"
    case "$cmd" in
        status)
            echo "status - $(t 'manager.cmd_status')"
            echo ""
            echo "  $(t 'manager.cmd_help'): ipban status"
            echo ""
            echo "$(t 'help.output')"
            echo "  - $(t 'help.chain_status')"
            echo "  - $(t 'help.banned_count')"
            echo "  - $(t 'help.recent_bans')"
            echo "  - $(t 'help.ban_history')"
            ;;
        ban)
            echo "ban <IP> [reason] - $(t 'manager.cmd_ban')"
            echo ""
            echo "$(t 'help.arguments')"
            echo "  IP      $(t 'help.ip_required')"
            echo "  reason  $(t 'help.reason_optional')"
            echo ""
            echo "$(t 'help.examples')"
            echo "  ipban ban 192.168.1.100"
            echo "  ipban ban 192.168.1.100 'SQL injection attack'"
            ;;
        unban)
            echo "unban <IP> - $(t 'manager.cmd_unban')"
            echo ""
            echo "$(t 'help.arguments')"
            echo "  IP  $(t 'help.ip_required')"
            echo ""
            echo "$(t 'help.examples')"
            echo "  ipban unban 192.168.1.100"
            ;;
        whitelist)
            echo "whitelist [add|del] <IP> - $(t 'manager.cmd_whitelist')"
            echo ""
            echo "$(t 'help.subcommands')"
            echo "  (none)      $(t 'help.wl_show')"
            echo "  add <IP>    $(t 'help.wl_add')"
            echo "  del <IP>    $(t 'help.wl_del')"
            echo ""
            echo "$(t 'help.examples')"
            echo "  ipban whitelist"
            echo "  ipban whitelist add 192.168.1.100"
            echo "  ipban whitelist del 192.168.1.100"
            ;;
        analyze)
            echo "analyze [options] - $(t 'manager.cmd_analyze')"
            echo ""
            echo "$(t 'help.options')"
            echo "  --full, -f          $(t 'manager.analyze_full')"
            echo "  --days N, -d N      $(t 'manager.analyze_days')"
            echo "  --threshold N, -t N $(t 'manager.analyze_threshold')"
            echo "  --preview, -p       $(t 'help.preview_mode')"
            echo ""
            echo "$(t 'help.examples')"
            echo "  ipban analyze --full"
            echo "  ipban analyze --days 7"
            echo "  ipban analyze --days 7 --threshold 10"
            echo "  ipban analyze --preview"
            ;;
        *)
            show_help
            ;;
    esac
}

cmd_check() {
    print_header "$(t 'manager.check_title')"
    echo ""
    
    local pass=0
    local fail=0
    
    printf "  %-25s " "$(t 'manager.check_python')"
    if command -v python3 >/dev/null 2>&1; then
        print_success "[$(t 'manager.check_pass')] $(python3 --version 2>&1)"
        pass=$((pass + 1))
    else
        print_error "[$(t 'manager.check_fail')]"
        fail=$((fail + 1))
    fi
    
    printf "  %-25s " "$(t 'manager.check_iptables')"
    if iptables -n -L >/dev/null 2>&1; then
        print_success "[$(t 'manager.check_pass')]"
        pass=$((pass + 1))
    else
        print_error "[$(t 'manager.check_fail')] ($(t 'help.need_root'))"
        fail=$((fail + 1))
    fi
    
    printf "  %-25s " "$(t 'manager.check_chain')"
    local chain_output=$(iptables -n -L "$IPTABLES_CHAIN" 2>/dev/null)
    if [ -n "$chain_output" ]; then
        local count=$(echo "$chain_output" | grep -c DROP)
        print_success "[$(t 'manager.check_pass')] $count IPs"
        pass=$((pass + 1))
    else
        print_warning "[$(t 'manager.check_fail')] ($(t 'help.not_initialized'))"
        fail=$((fail + 1))
    fi
    
    printf "  %-25s " "$(t 'manager.check_config')"
    if [ -f "$CONFIG_FILE" ]; then
        print_success "[$(t 'manager.check_pass')]"
        pass=$((pass + 1))
    else
        print_error "[$(t 'manager.check_fail')]"
        fail=$((fail + 1))
    fi
    
    printf "  %-25s " "$(t 'manager.check_whitelist')"
    if [ -f "$ALLOW_FILE" ]; then
        local wl_count=$(grep -cvE '^#|^$' "$ALLOW_FILE" 2>/dev/null || echo 0)
        print_success "[$(t 'manager.check_pass')] $wl_count IPs"
        pass=$((pass + 1))
    else
        print_warning "[$(t 'manager.check_fail')] ($(t 'help.will_create'))"
        fail=$((fail + 1))
    fi
    
    echo ""
    print_info "$(t 'manager.check_pass'): $pass, $(t 'manager.check_fail'): $fail"
}

cmd_status() {
    print_header "$(t 'manager.ban_status')"
    echo ""
    
    if iptables -n -L "$IPTABLES_CHAIN" >/dev/null 2>&1; then
        local total=$(iptables -n -L "$IPTABLES_CHAIN" 2>/dev/null | grep -c DROP)
        print_info "$(t 'manager.chain'): $IPTABLES_CHAIN"
        print_info "$(t 'manager.ban_count'): $total"
        echo ""
        
        if [ "$total" -gt 0 ]; then
            print_info "$(t 'manager.recent_bans'):"
            iptables -n -L "$IPTABLES_CHAIN" --line-numbers 2>/dev/null | grep DROP | tail -10 | while read -r num rest; do
                local ip=$(echo "$rest" | awk '{print $4}')
                printf "    %-6s %s\n" "#$num" "$ip"
            done
        fi
    else
        print_warning "$(t 'manager.chain') $IPTABLES_CHAIN $(t 'manager.file_not_exist')"
    fi
    
    echo ""
    print_info "$(t 'manager.ban_list'): $PENDING_FILE"
    if [ -f "$PENDING_FILE" ]; then
        local count=$(wc -l < "$PENDING_FILE")
        print_info "  $count $(t 'manager.records')"
    else
        print_warning "  $(t 'manager.file_not_exist')"
    fi
    
    echo ""
    print_info "$(t 'manager.recent_history'):"
    if [ -f "$HISTORY_FILE" ]; then
        tail -5 "$HISTORY_FILE" | while read -r line; do
            echo "  $line"
        done
    else
        print_warning "  $(t 'manager.no_history')"
    fi
}

cmd_list() {
    print_header "$(t 'manager.list_title')"
    echo ""
    
    if iptables -n -L "$IPTABLES_CHAIN" >/dev/null 2>&1; then
        local total=$(iptables -n -L "$IPTABLES_CHAIN" 2>/dev/null | grep -c DROP)
        if [ "$total" -gt 0 ]; then
            printf "%-6s %-18s %s\n" "$(t 'manager.list_no')" "$(t 'manager.list_ip')" "$(t 'manager.list_target')"
            echo "----------------------------------------"
            iptables -n -L "$IPTABLES_CHAIN" --line-numbers 2>/dev/null | grep DROP | while read -r num rest; do
                local ip=$(echo "$rest" | awk '{print $4}')
                printf "%-6s %-18s %s\n" "#$num" "$ip" "DROP"
            done
        else
            print_info "$(t 'manager.no_bans')"
        fi
    else
        print_warning "$(t 'manager.file_not_exist')"
    fi
}

cmd_ban() {
    require_root
    local ip="$1"
    local reason="${2:-manual}"
    
    if [ -z "$ip" ]; then
        print_error "$(t 'manager.usage'): ipban ban <IP> [reason]"
        exit 1
    fi
    
    if ! validate_ip "$ip"; then
        print_error "$(t 'manager.invalid_ip'): $ip"
        exit 1
    fi
    
    if is_private_ip "$ip"; then
        print_warning "$(t 'manager.ban_private_warn'): $ip"
    fi
    
    if is_in_whitelist "$ip" "$ALLOW_FILE"; then
        print_warning "$(t 'manager.ban_whitelist_warn'): $ip"
    fi
    
    if iptables -n -L "$IPTABLES_CHAIN" 2>/dev/null | grep -qw "$ip"; then
        print_warning "$ip $(t 'manager.ban_exists')"
        exit 0
    fi
    
    if ! iptables -n -L "$IPTABLES_CHAIN" >/dev/null 2>&1; then
        iptables -N "$IPTABLES_CHAIN" 2>/dev/null
        iptables -I INPUT -j "$IPTABLES_CHAIN" 2>/dev/null
    fi
    
    iptables -I "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null
    
    if [ -d /etc/iptables ] 2>/dev/null || mkdir -p /etc/iptables 2>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
    elif [ -d /etc/sysconfig ] 2>/dev/null || mkdir -p /etc/sysconfig 2>/dev/null; then
        iptables-save > /etc/sysconfig/iptables 2>/dev/null
    fi
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$ip # $timestamp 1$(t 'manager.times') [manual,$reason]" >> "$PENDING_FILE"
    echo "$timestamp | $ip | 1 | manual,$reason" >> "$HISTORY_FILE"
    echo "$ip" >> "$APPLIED_FILE"
    
    print_success "$(t 'manager.ban_done'): $ip"
}

cmd_unban() {
    require_root
    local ip="$1"
    
    if [ -z "$ip" ]; then
        print_error "$(t 'manager.usage'): ipban unban <IP>"
        exit 1
    fi
    
    if ! validate_ip "$ip"; then
        print_error "$(t 'manager.invalid_ip'): $ip"
        exit 1
    fi
    
    if iptables -n -L "$IPTABLES_CHAIN" 2>/dev/null | grep -qw "$ip"; then
        while iptables -D "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null; do
            :
        done
        print_success "$(t 'manager.unban_done'): $ip"
        
        if [ -f "$APPLIED_FILE" ]; then
            local escaped_ip=$(escape_for_sed "$ip")
            sed -i "/^${escaped_ip}$/d" "$APPLIED_FILE"
        fi
    else
        print_warning "$ip $(t 'manager.unban_not_found')"
    fi
}

cmd_flush() {
    require_root
    print_warning "$(t 'manager.flush_warn')"
    read -p "$(t 'manager.confirm') " confirm
    
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        if iptables -n -L "$IPTABLES_CHAIN" >/dev/null 2>&1; then
            iptables -F "$IPTABLES_CHAIN"
            if iptables -n -L INPUT 2>/dev/null | grep "$IPTABLES_CHAIN" >/dev/null 2>&1; then
                iptables -D INPUT -j "$IPTABLES_CHAIN"
            fi
            iptables -X "$IPTABLES_CHAIN"
        fi
        touch "$APPLIED_FILE" 2>/dev/null
        > "$APPLIED_FILE"
        print_success "$(t 'manager.flush_done')"
    else
        print_info "$(t 'manager.cancelled')"
    fi
}

cmd_cleanup() {
    local days="${1:-$DAYS_TO_KEEP}"
    
    print_info "$(t 'manager.cleanup') $days $(t 'manager.days_ago')"
    
    if [ -f "$HISTORY_FILE" ]; then
        local tmp_file=$(mktemp "${HISTORY_FILE}.XXXXXX")
        
        if date -d "2024-01-01" '+%Y-%m-%d' >/dev/null 2>&1; then
            local find_date=$(date -d "-${days} days" '+%Y-%m-%d')
        else
            local find_date=$(date -v-${days}d '+%Y-%m-%d')
        fi
        
        awk -v d="$find_date" '$0 >= d' "$HISTORY_FILE" > "$tmp_file"
        mv "$tmp_file" "$HISTORY_FILE"
        print_success "$(t 'manager.cleanup_done')"
    fi
}

cmd_whitelist() {
    local action="$1"
    local ip="$2"
    
    case "$action" in
        add)
            if [ -z "$ip" ]; then
                print_error "$(t 'manager.usage'): ipban whitelist add <IP|CIDR>"
                exit 1
            fi
            if ! validate_ip_or_cidr "$ip"; then
                print_error "$(t 'manager.invalid_ip'): $ip"
                exit 1
            fi
            if grep -qxF "$ip" "$ALLOW_FILE" 2>/dev/null; then
                print_warning "$ip $(t 'manager.wl_exists')"
                exit 0
            fi
            echo "$ip" >> "$ALLOW_FILE"
            print_success "$(t 'manager.wl_add_done'): $ip"
            ;;
        del|remove)
            if [ -z "$ip" ]; then
                print_error "$(t 'manager.usage'): ipban whitelist del <IP|CIDR>"
                exit 1
            fi
            if ! validate_ip_or_cidr "$ip"; then
                print_error "$(t 'manager.invalid_ip'): $ip"
                exit 1
            fi
            if [ -f "$ALLOW_FILE" ] && grep -qxF "$ip" "$ALLOW_FILE"; then
                local escaped_ip=$(escape_for_sed "$ip")
                sed -i "/^${escaped_ip}$/d" "$ALLOW_FILE"
                print_success "$(t 'manager.wl_del_done'): $ip"
            else
                print_warning "$ip $(t 'manager.wl_not_found')"
            fi
            ;;
        *)
            print_header "$(t 'manager.wl_title')"
            echo ""
            print_info "$(t 'manager.wl_file'): $ALLOW_FILE"
            echo ""
            
            if [ -f "$ALLOW_FILE" ]; then
                local ips=$(grep -v '^#' "$ALLOW_FILE" | grep -v '^$')
                if [ -n "$ips" ]; then
                    print_info "$(t 'manager.wl_current'):"
                    echo "$ips" | while read -r line; do
                        echo "  $line"
                    done
                else
                    print_info "$(t 'manager.wl_empty')"
                fi
            else
                print_warning "$(t 'manager.wl_not_exist')"
            fi
            echo ""
            print_info "$(t 'help.commands')"
            echo "  ipban whitelist add <IP|CIDR>"
            echo "  ipban whitelist del <IP|CIDR>"
            ;;
    esac
}

cmd_stats() {
    print_header "$(t 'manager.stats_title')"
    echo ""
    
    local today=$(date '+%Y-%m-%d')
    
    if [ -f "$HISTORY_FILE" ]; then
        local today_count=$(grep "^$today" "$HISTORY_FILE" 2>/dev/null | wc -l)
        local total_count=$(wc -l < "$HISTORY_FILE")
        
        print_info "$(t 'manager.stats_today'): $today_count"
        print_info "$(t 'manager.stats_total'): $total_count"
        echo ""
        
        print_info "$(t 'manager.stats_top'):"
        awk -F'|' '{print $4}' "$HISTORY_FILE" 2>/dev/null | \
            sort | uniq -c | sort -rn | head -5 | \
            while read -r count type; do
                printf "  %-30s %s\n" "$(echo "$type" | xargs)" "$count"
            done
    else
        print_warning "$(t 'manager.no_history')"
    fi
}

cmd_logs() {
    local lines="${1:-20}"
    
    print_header "$(t 'manager.logs_title') ($(t 'manager.logs_last') $lines $(t 'manager.logs_lines'))"
    echo ""
    
    if [ -f "$MAIN_LOG" ]; then
        tail -"$lines" "$MAIN_LOG"
    else
        print_warning "$(t 'manager.file_not_exist'): $MAIN_LOG"
    fi
}

backup_config() {
    local reason="${1:-manual}"
    local backup_dir="/var/lib/ip-ban-hammer/config_backups"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_file="${backup_dir}/security.conf.${timestamp}"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        return 1
    fi
    
    mkdir -p "$backup_dir"
    
    cp "$CONFIG_FILE" "$backup_file"
    
    echo "$timestamp | $reason" >> "${backup_dir}/backup_history.log"
    
    echo "$backup_file"
    return 0
}

list_config_backups() {
    local backup_dir="/var/lib/ip-ban-hammer/config_backups"
    
    if [ ! -d "$backup_dir" ]; then
        print_warning "$(t 'config.no_backups')"
        return 0
    fi
    
    local backups=($(ls -t "${backup_dir}/security.conf".* 2>/dev/null | head -20))
    
    if [ ${#backups[@]} -eq 0 ]; then
        print_warning "$(t 'config.no_backups')"
        return 0
    fi
    
    print_header "$(t 'config.backup_list')"
    echo ""
    
    local i=1
    for backup in "${backups[@]}"; do
        local basename=$(basename "$backup")
        local timestamp=${basename#security.conf.}
        local size=$(du -h "$backup" 2>/dev/null | cut -f1)
        local reason=""
        if [ -f "${backup_dir}/backup_history.log" ]; then
            reason=$(grep "^$timestamp" "${backup_dir}/backup_history.log" 2>/dev/null | cut -d'|' -f2- | sed 's/^[[:space:]]*//')
        fi
        printf "  %2d) %s  (%s)  %s\n" "$i" "$timestamp" "$size" "${reason:-$(t 'config.backup_manual')}"
        i=$((i + 1))
    done
    
    echo ""
    print_info "$(t 'config.backup_restore_hint')"
}

restore_config() {
    local backup_ref="$1"
    local backup_dir="/var/lib/ip-ban-hammer/config_backups"
    
    if [ -z "$backup_ref" ]; then
        print_error "$(t 'config.restore_usage')"
        return 1
    fi
    
    local backup_file=""
    
    if [[ "$backup_ref" =~ ^[0-9]+$ ]]; then
        local backups=($(ls -t "${backup_dir}/security.conf".* 2>/dev/null | head -20))
        if [ "$backup_ref" -ge 1 ] && [ "$backup_ref" -le ${#backups[@]} ]; then
            backup_file="${backups[$((backup_ref - 1))]}"
        fi
    else
        backup_file="${backup_dir}/security.conf.${backup_ref}"
    fi
    
    if [ ! -f "$backup_file" ]; then
        print_error "$(t 'config.backup_not_found'): $backup_ref"
        return 1
    fi
    
    local current_backup=$(backup_config "pre-restore")
    if [ -n "$current_backup" ]; then
        print_info "$(t 'config.backup_created'): $(basename $current_backup)"
    fi
    
    cp "$backup_file" "$CONFIG_FILE"
    print_success "$(t 'config.restore_success'): $(basename $backup_file)"
}

cmd_config() {
    local action="${1:-show}"
    local key="$2"
    local value="$3"
    
    case "$action" in
        show|"")
            print_header "$(t 'manager.cur_config')"
            echo ""
            if [ -f "$CONFIG_FILE" ]; then
                cat "$CONFIG_FILE"
            else
                print_warning "$(t 'manager.cur_config_not'): $CONFIG_FILE"
            fi
            ;;
        get)
            if [ -z "$key" ]; then
                print_error "$(t 'config.get_usage')"
                print_info "$(t 'config.get_example')"
                exit 1
            fi
            
            local section="${key%%.*}"
            local config_key="${key#*.}"
            
            if [ -f "$CONFIG_FILE" ]; then
                local result=$(awk -F= "/^\[$section\]/{f=1} f&&/^$config_key=/{print substr(\$0,index(\$0,\"=\")+1); exit}" "$CONFIG_FILE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                if [ -n "$result" ]; then
                    echo "$result"
                else
                    print_warning "$(t 'config.key_not_found'): $key"
                    exit 1
                fi
            else
                print_error "$(t 'config.file_not_found'): $CONFIG_FILE"
                exit 1
            fi
            ;;
        set)
            if [ -z "$key" ] || [ -z "$value" ]; then
                print_error "$(t 'config.set_usage')"
                print_info "$(t 'config.set_example')"
                exit 1
            fi
            
            local section="${key%%.*}"
            local config_key="${key#*.}"
            
            if [ ! -f "$CONFIG_FILE" ]; then
                print_error "$(t 'config.file_not_found'): $CONFIG_FILE"
                exit 1
            fi
            
            local tmp_file=$(mktemp "${CONFIG_FILE}.XXXXXX")
            local in_section=0
            local found=0
            
            local backup_result=$(backup_config "set:$key=$value")
            if [ -n "$backup_result" ]; then
                print_info "$(t 'config.backup_created'): $(basename $backup_result)"
            fi
            
            while IFS= read -r line; do
                if [[ "$line" =~ ^\[$section\] ]]; then
                    in_section=1
                    echo "$line" >> "$tmp_file"
                elif [[ "$line" =~ ^\[ ]] && [ "$in_section" -eq 1 ]; then
                    if [ "$found" -eq 0 ]; then
                        echo "$config_key = $value" >> "$tmp_file"
                        found=1
                    fi
                    in_section=0
                    echo "$line" >> "$tmp_file"
                elif [ "$in_section" -eq 1 ] && [[ "$line" =~ ^$config_key[[:space:]]*= ]]; then
                    echo "$config_key = $value" >> "$tmp_file"
                    found=1
                else
                    echo "$line" >> "$tmp_file"
                fi
            done < "$CONFIG_FILE"
            
            if [ "$found" -eq 0 ] && [ "$in_section" -eq 1 ]; then
                echo "$config_key = $value" >> "$tmp_file"
            fi
            
            if [ "$found" -eq 0 ] && [ "$in_section" -eq 0 ]; then
                echo "" >> "$tmp_file"
                echo "[$section]" >> "$tmp_file"
                echo "$config_key = $value" >> "$tmp_file"
            fi
            
            mv "$tmp_file" "$CONFIG_FILE"
            print_success "$(t 'config.set_success') $key = $value"
            ;;
        edit)
            local editor="${EDITOR:-vi}"
            if [ -f "$CONFIG_FILE" ]; then
                local backup_result=$(backup_config "edit")
                if [ -n "$backup_result" ]; then
                    print_info "$(t 'config.backup_created'): $(basename $backup_result)"
                fi
                $editor "$CONFIG_FILE"
            else
                print_error "$(t 'config.file_not_found'): $CONFIG_FILE"
                exit 1
            fi
            ;;
        backup)
            local backup_result=$(backup_config "manual")
            if [ -n "$backup_result" ]; then
                print_success "$(t 'config.backup_created'): $(basename $backup_result)"
            else
                print_error "$(t 'config.backup_failed')"
                exit 1
            fi
            ;;
        backups)
            list_config_backups
            ;;
        restore)
            restore_config "$key"
            ;;
        *)
            print_error "$(t 'config.unknown_action'): $action"
            print_info "$(t 'config.usage')"
            exit 1
            ;;
    esac
}

cmd_analyze() {
    local args=()
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --full|-f)
                args+=("--full")
                shift
                ;;
            --days|-d)
                if [ -n "$2" ] && [[ ! "$2" =~ ^- ]]; then
                    args+=("--days" "$2")
                    shift 2
                else
                    print_error "$(t 'manager.usage'): ipban analyze --days <N>"
                    exit 1
                fi
                ;;
            --threshold|-t)
                if [ -n "$2" ] && [[ ! "$2" =~ ^- ]]; then
                    args+=("--threshold" "$2")
                    shift 2
                else
                    print_error "$(t 'manager.usage'): ipban analyze --threshold <N>"
                    exit 1
                fi
                ;;
            --preview|-p)
                args+=("--preview")
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
    
    /usr/bin/python3 "$ROOT_DIR/bin/full_scan.py" "${args[@]}"
}

if [ "$#" -eq 0 ]; then
    show_help
    exit 0
fi

case "$1" in
    -h|--help|help)
        if [ -n "$2" ]; then
            show_help_command "$2"
        else
            show_help
        fi
        ;;
    -V|--version|version)
        show_version
        ;;
    status)
        cmd_status
        ;;
    list)
        cmd_list
        ;;
    ban)
        cmd_ban "$2" "$3"
        ;;
    unban)
        cmd_unban "$2"
        ;;
    flush)
        cmd_flush
        ;;
    cleanup)
        cmd_cleanup "$2"
        ;;
    whitelist|wl)
        cmd_whitelist "$2" "$3"
        ;;
    stats)
        cmd_stats
        ;;
    logs)
        cmd_logs "$2"
        ;;
    check)
        cmd_check
        ;;
    config)
        shift
        cmd_config "$@"
        ;;
    analyze)
        shift
        cmd_analyze "$@"
        ;;
    *)
        print_error "$(t 'manager.invalid_cmd'): $1"
        echo ""
        show_help
        exit 1
        ;;
esac
