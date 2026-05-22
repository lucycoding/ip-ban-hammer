_ipban_completion() {
    local cur prev words cword
    _init_completion || return
    
    local commands="status list ban unban flush cleanup whitelist analyze stats logs check config version help"
    local whitelist_subcmds="add del"
    local analyze_options="--full -f --days -d --threshold -t"
    
    local chain_name="IP_BAN_HAMMER"
    if [ -f /etc/ip-ban-hammer/security.conf ]; then
        chain_name=$(awk -F= '/^\[iptables\]/{f=1} f&&/^chain_name=/{print substr($0,index($0,"=")+1); exit}' /etc/ip-ban-hammer/security.conf 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        chain_name=${chain_name:-IP_BAN_HAMMER}
    fi
    
    case ${prev} in
        ipban)
            COMPREPLY=($(compgen -W "$commands" -- ${cur}))
            return
            ;;
        whitelist|wl)
            COMPREPLY=($(compgen -W "$whitelist_subcmds" -- ${cur}))
            return
            ;;
        analyze)
            COMPREPLY=($(compgen -W "$analyze_options" -- ${cur}))
            return
            ;;
        ban|unban)
            if iptables -n -L "$chain_name" >/dev/null 2>&1; then
                local banned_ips=$(iptables -n -L "$chain_name" 2>/dev/null | grep DROP | awk '{print $4}' | sort -u)
                COMPREPLY=($(compgen -W "$banned_ips" -- ${cur}))
            fi
            return
            ;;
        cleanup)
            COMPREPLY=($(compgen -W "7 14 30 60 90" -- ${cur}))
            return
            ;;
        logs)
            COMPREPLY=($(compgen -W "10 20 50 100" -- ${cur}))
            return
            ;;
        --days|-d)
            COMPREPLY=($(compgen -W "1 7 14 30" -- ${cur}))
            return
            ;;
        --threshold|-t)
            COMPREPLY=($(compgen -W "3 5 10 20" -- ${cur}))
            return
            ;;
        help)
            COMPREPLY=($(compgen -W "$commands" -- ${cur}))
            return
            ;;
    esac
}

complete -F _ipban_completion ipban
