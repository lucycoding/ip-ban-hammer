<div align="center">

# IP Ban Hammer

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)]()
[![Language](https://img.shields.io/badge/language-Python%20%7C%20Bash-green.svg)]()
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)]()

**自动分析网站日志，检测攻击IP并封禁**

[English](#english) | [中文](#中文)

</div>

---

## 中文

### 功能特点

- 交互式安装：10步引导，自动检测日志、本机IP，场景化配置
- 多日志源支持：可配置多个日志文件路径（逗号分隔）
- 中英文切换：安装时选择，运行时通过配置切换
- 自动封禁：检测攻击IP并自动添加到iptables
- 白名单支持：支持单个IP和CIDR网段，白名单IP不会被封禁
- 私有IP跳过：自动跳过内网IP封禁，防止误封
- 告警通知：支持 Webhook 和 Email 告警通知
- 预览模式：`--preview` 预览将要封禁的IP，不实际写入
- 完整卸载：支持完全卸载，不影响其他iptables规则
- 性能优化：大文件反向读取，快速定位最近日志
- 全量扫描：支持全量日志分析，带进度条显示
- systemd支持：可选 systemd timers 替代 cron
- 备份回滚：支持备份和恢复 iptables 规则与数据文件
- 配置备份：配置修改时自动备份，支持查看和恢复历史配置

### 环境要求

| 组件 | 最低版本 | 推荐版本 | 说明 |
|-----|---------|---------|------|
| **Linux** | CentOS 7+ / Ubuntu 16.04+ / Debian 9+ | CentOS 8+ / Ubuntu 20.04+ | 需支持systemd |
| **Python** | 3.6+ | 3.8+ | 核心分析脚本（仅标准库，无第三方依赖） |
| **Bash** | 4.0+ | 4.2+ | Shell脚本（需要关联数组支持） |
| **iptables** | 1.4.21+ | 1.6+ | 防火墙管理 |

### 快速安装

```bash
cd ip-ban-hammer
chmod +x install.sh
./install.sh
```

> **注意**：请使用 `bash install.sh` 或 `./install.sh` 执行，不要使用 `sh install.sh`。脚本需要 Bash 4.0+ 支持。

安装过程（10步）：
1. **创建目录** - 创建安装目录、配置目录、数据目录、日志目录
2. **检测日志文件** - 自动检测 `/www/wwwlogs/*.log`、`/var/log/nginx/access.log` 等
3. **配置白名单IP** - 自动检测本机IP（内网+公网），询问是否添加
4. **选择封禁策略** - 根据网站类型选择预设策略或自定义
5. **高级配置** - 可选配置iptables链名、历史保留天数、cron频率
6. **复制脚本** - 复制可执行脚本到 `/opt/ip-ban-hammer/bin/`
7. **生成配置** - 根据安装选项生成运行时配置文件
8. **设置权限** - 配置文件和数据文件权限设为 600
9. **配置定时任务** - 添加日志分析、应用封禁、清理历史的cron任务
10. **安装命令** - 创建 `ipban` 命令链接和Shell补全

### 封禁策略预设

| 策略 | 攻击阈值 | 时间窗口 | 适用场景 |
|-----|---------|---------|---------|
| 个人博客/小型网站 | 3次 | 30分钟 | 快速响应，低流量 |
| 企业官网/中型网站 | 5次 | 30分钟 | 平衡模式，推荐选择 |
| 电商平台/大型网站 | 10次 | 20分钟 | 避免误封，高流量 |
| API服务/高频请求 | 15次 | 10分钟 | 短窗口，高频请求 |

### 攻击检测类型

系统检测以下11种攻击类型：

| 类型 | 检测内容 |
|-----|---------|
| **SQL Injection** | UNION SELECT, INSERT INTO, DROP TABLE, SLEEP(), BENCHMARK() 等 |
| **XSS Attack** | javascript:, on\*=, \<script\>, \<iframe\> 等 |
| **Path Traversal** | ../, /etc/passwd, /etc/shadow 等 |
| **Command Injection** | ;cat, \|bash, ;wget, ;curl, 反引号执行 等 |
| **Scanner** | nikto, sqlmap, nmap, masscan, acunetix, nessus 等 |
| **Sensitive File Probe** | .git, .env, .htaccess, backup, phpmyadmin 等 |
| **Webshell** | cmd.php, shell.php, eval(), base64_decode(), system() 等 |
| **Vulnerability Probe** | autodiscover, owa, thinkphp, jndi:, ldap:, rmi: 等 |
| **Protocol Attack** | 十六进制编码, CONNECT 方法 等 |
| **Proxy Attack** | GET http://, POST http://, CONNECT IP:port 等 |
| **AI API Probe** | /v1/models, /v1/chat/completions, /v1/embeddings 等大模型接口扫描 |

### 升级更新

```bash
# 交互式升级
./install.sh

# 非交互式升级（默认合并配置）
./install.sh --upgrade

# 指定语言
./install.sh --lang zh
./install.sh --lang en --upgrade
```

**配置处理方式：**

| 方式 | 说明 | 适用场景 |
|-----|------|---------|
| 覆盖 | 使用新版默认配置 | 配置改动少，想用新默认值 |
| 保留 | 保持旧配置不变 | 配置改动多，手动处理新项 |
| 合并 | 保留自定义值 + 添加新配置项 | 推荐，兼顾自定义和新功能 |

### 配置文件

编辑 `/etc/ip-ban-hammer/security.conf`：

```ini
[paths]
# 日志文件（多个用逗号分隔）
log_files = /www/wwwlogs/www.log
# 数据文件
pending = /var/lib/ip-ban-hammer/pending.list
applied = /var/lib/ip-ban-hammer/applied.list
allow = /etc/ip-ban-hammer/allow.list
# 日志文件
main_log = /var/log/ip-ban-hammer/main.log
history = /var/log/ip-ban-hammer/history.log
stats = /var/log/ip-ban-hammer/stats.log

[iptables]
# iptables链名称（如与其他工具冲突可修改）
chain_name = IP_BAN_HAMMER

[thresholds]
# 触发封禁的攻击次数
attack_threshold = 5
# 攻击计数时间窗口（分钟）
time_window_minutes = 30
# 历史记录保留天数
days_to_keep = 30
# 大文件反向读取阈值（MB）
reverse_read_threshold_mb = 100

[cron]
# 日志分析频率（建议与time_window_minutes匹配或更短）
analyze_cron = */30 * * * *
# 封禁应用频率（保持每分钟以及时封禁）
apply_cron = * * * * *
# 历史清理时间（默认每天3点）
cleanup_cron = 0 3 * * *

[general]
# 语言: zh (中文) 或 en (英文)
language = zh
# 彩色输出: true 或 false
color_output = true

[security]
# 跳过私有/保留IP地址的封禁
# 包括: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 等
skip_private_ip = true
# IP位置检测模式: auto(自动检测), first(行首), forwarded(X-Forwarded-For), json, custom
log_ip_position = auto
# json_ip_key = remote_addr     # json模式时使用的键名
# custom_ip_regex =             # custom模式时的正则表达式

[alert]
# 告警通知配置（可选）
# 选择 webhook 或 email，二选一（webhook 优先）

# Webhook URL（HTTP POST 通知）
# webhook_url = https://hooks.slack.com/services/XXX/YYY/ZZZ
# webhook_url = 

# Email 收件人（需要 mail/sendmail 命令）
# email_to = admin@example.com

# Email 发件人（可选）
# email_sender = ipban-noreply@example.com
```

**配置示例文件：**
- 源码包：`config/security.conf.example`, `config/allow.list.example`
- 安装后复制到：`/opt/ip-ban-hammer/config/` 供参考
- 运行时配置：`/etc/ip-ban-hammer/` （修改此目录的文件生效）

### 白名单配置

支持单个 IP 和 CIDR 网段格式。

编辑 `/etc/ip-ban-hammer/allow.list`：

```
# IP Ban Hammer Allow List
# 每行一个IP或CIDR，#开头的行为注释

# 单个 IP
127.0.0.1
192.168.1.100

# CIDR 网段
10.0.0.0/8           # 内网 10.x.x.x
172.16.0.0/12        # 内网 172.16-31.x.x
192.168.0.0/16       # 内网 192.168.x.x

# 搜索引擎 IP 段（可选）
66.249.64.0/19       # Google
123.125.0.0/16       # Baidu
220.181.0.0/16       # Baidu
```

**安装时自动检测：**
- 内网IP：127.0.0.1, hostname -I 获取的所有本地IP
- 公网IP：通过 ifconfig.me / ip.sb / icanhazip.com 获取

### 管理命令

```bash
# 查看帮助
ipban --help
ipban -h                    # 短标志
ipban help status           # 查看特定命令帮助

# 查看版本
ipban version
ipban -V                    # 短标志

# 查看状态
ipban status

# 列出所有封禁IP
ipban list

# 手动封禁IP
ipban ban 1.2.3.4
ipban ban 1.2.3.4 "SQL injection attack"  # 带原因

# 解封IP
ipban unban 1.2.3.4

# 清除所有封禁
ipban flush

# 清理历史记录
ipban cleanup 30

# 白名单管理（支持 IP 和 CIDR）
ipban whitelist
ipban wl                    # 短别名
ipban whitelist add 1.2.3.4
ipban whitelist add 10.0.0.0/8   # 添加 CIDR 网段
ipban wl del 1.2.3.4

# 分析日志
ipban analyze --full              # 全量分析
ipban analyze --days 7            # 分析最近7天
ipban analyze --days 7 --threshold 10  # 指定阈值
ipban analyze --preview           # 预览模式（不写入文件）

# 应用封禁（dry-run 模式）
/opt/ip-ban-hammer/bin/apply_iptables_ban.sh --dry-run

# 统计信息
ipban stats

# 查看日志
ipban logs
ipban logs 50  # 显示最近50行

# 配置管理
ipban config                          # 显示完整配置
ipban config get thresholds.attack_threshold  # 获取配置值
ipban config set thresholds.attack_threshold 10  # 设置配置值
ipban config edit                     # 编辑器打开配置
ipban config backup                   # 手动备份配置
ipban config backups                  # 查看备份列表
ipban config restore 1                # 恢复到第1个备份

# 系统检查
ipban check
```

### 定时任务

**方式一：cron（默认）**

安装后自动添加（`/etc/cron.d/ip-ban-hammer`）：
- 每30分钟：分析日志（可通过高级配置修改）
- 每分钟：应用封禁规则
- 每天3点：清理历史记录（可通过高级配置修改）

**方式二：systemd（可选）**

安装时如检测到 systemd，可选择使用 systemd timers：
```bash
# 查看定时器状态
systemctl list-timers | grep ipban

# 手动触发分析
systemctl start ipban-analyze.service

# 手动触发封禁应用
systemctl start ipban-apply.service
```

### 卸载

```bash
/opt/ip-ban-hammer/bin/uninstall.sh
```

**卸载时保留的文件（需手动删除）：**
- 配置文件：`/etc/ip-ban-hammer/`
- 数据文件：`/var/lib/ip-ban-hammer/`
- 日志文件：`/var/log/ip-ban-hammer/`

### 目录结构

```
/opt/ip-ban-hammer/               # 脚本目录
├── bin/
│   ├── auto_ban_attacks.py      # 日志分析器 - 定时分析
│   ├── full_scan.py             # 全量扫描 - 手动分析
│   ├── apply_iptables_ban.sh    # 应用iptables规则
│   ├── ban_manager.sh           # 管理工具
│   └── uninstall.sh             # 卸载脚本
├── config/
│   ├── security.conf.example    # 配置示例
│   └── allow.list.example       # 白名单示例
├── lib/
│   ├── ipban_core/              # 共享模块库
│   │   ├── __init__.py          # 模块入口
│   │   ├── patterns.py          # 攻击模式定义
│   │   ├── validators.py        # IP/CIDR 验证
│   │   ├── config.py            # 配置加载
│   │   ├── whitelist.py         # 白名单处理
│   │   ├── alert.py             # 告警通知
│   │   ├── migration.py         # 配置迁移
│   │   ├── backup.py            # 备份回滚
│   │   └── log_parser.py        # 日志解析
│   └── completion/
│       └── ipban.bash            # Bash补全
└── systemd/                      # systemd 服务文件（可选）
    ├── ipban-analyze.service
    ├── ipban-analyze.timer
    ├── ipban-apply.service
    ├── ipban-apply.timer
    ├── ipban-cleanup.service
    └── ipban-cleanup.timer

/etc/ip-ban-hammer/               # 运行时配置
├── security.conf                # 运行时配置（修改此文件生效）
├── allow.list                   # 白名单
└── i18n/
    └── zh.lang                  # 语言文件

/var/lib/ip-ban-hammer/           # 数据文件
├── pending.list                 # 待封禁IP
├── applied.list                 # 已封禁IP
├── config_backups/              # 配置备份目录
│   ├── security.conf.YYYYMMDD_HHMMSS  # 配置备份文件
│   └── backup_history.log      # 备份历史记录
└── backups/                     # iptables备份目录
    └── backup_YYYYMMDD_HHMMSS/  # 备份文件

/var/log/ip-ban-hammer/           # 日志文件
├── main.log                     # 运行日志
├── history.log                  # 封禁历史
├── stats.log                    # 统计数据
└── ipv6_detected.log            # IPv6检测日志
```

### 常见问题

| 问题 | 解决方案 |
|------|----------|
| `python3: command not found` | 安装Python 3: `yum install python3` |
| `iptables: command not found` | 安装iptables: `yum install iptables` |
| Permission denied | 使用root或sudo运行 |
| 定时任务未执行 | 检查: `cat /etc/cron.d/ip-ban-hammer` |
| 封禁不生效 | 检查: `iptables -n -L IP_BAN_HAMMER` |

---

## English

### Features

- Interactive installation: 10-step guided setup, auto-detect logs, local IPs, scenario-based config
- Multiple log sources: configurable log file paths (comma-separated)
- i18n support: select during install, switch via config at runtime
- Auto-ban: detect attack IPs and add to iptables
- Whitelist support: supports single IP and CIDR notation, whitelisted IPs won't be banned
- Private IP skip: automatically skip private/reserved IPs from banning
- Alert notifications: Webhook and Email alert support
- Preview mode: `--preview` to see IPs without writing to files
- Clean uninstall: remove without affecting other iptables rules
- Performance optimization: reverse reading for large files
- Full scan: full log analysis with progress bar
- systemd support: optional systemd timers as alternative to cron
- Backup & rollback: backup and restore iptables rules, data files, and config
- Config backup: auto-backup on config changes, view and restore history

### Requirements

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| **Linux** | CentOS 7+ / Ubuntu 16.04+ / Debian 9+ | CentOS 8+ / Ubuntu 20.04+ | systemd support required |
| **Python** | 3.6+ | 3.8+ | Core analyzer (stdlib only, no deps) |
| **Bash** | 4.0+ | 4.2+ | Shell scripts (associative arrays) |
| **iptables** | 1.4.21+ | 1.6+ | Firewall management |

### Quick Install

```bash
cd ip-ban-hammer
chmod +x install.sh
./install.sh
```

> **Note**: Use `bash install.sh` or `./install.sh` to run the script. Do not use `sh install.sh`. Bash 4.0+ is required.

Installation process (10 steps):
1. **Create directories** - Install, config, data, and log directories
2. **Detect log files** - Auto-detect `/www/wwwlogs/*.log`, `/var/log/nginx/access.log`, etc.
3. **Configure whitelist** - Auto-detect local IPs (private + public), ask to add
4. **Select ban policy** - Choose preset by site type or customize
5. **Advanced config** - Optional: iptables chain name, history retention, cron frequency
6. **Copy scripts** - Copy executables to `/opt/ip-ban-hammer/bin/`
7. **Generate config** - Create runtime config based on installation options
8. **Set permissions** - Set config and data files to 600
9. **Setup cron** - Add cron jobs for analysis, ban application, cleanup
10. **Install command** - Create `ipban` symlink and shell completion

### Ban Policy Presets

| Policy | Threshold | Window | Use Case |
|--------|-----------|--------|----------|
| Personal Blog/Small Site | 3 | 30min | Fast response, low traffic |
| Corporate/Medium Site | 5 | 30min | Balanced mode, recommended |
| E-commerce/Large Site | 10 | 20min | Avoid false positives, high traffic |
| API Service/High Frequency | 15 | 10min | Short window, high frequency |

### Attack Detection Types

The system detects 11 attack types:

| Type | Detection |
|------|-----------|
| **SQL Injection** | UNION SELECT, INSERT INTO, DROP TABLE, SLEEP(), BENCHMARK(), etc. |
| **XSS Attack** | javascript:, on\*=, \<script\>, \<iframe\>, etc. |
| **Path Traversal** | ../, /etc/passwd, /etc/shadow, etc. |
| **Command Injection** | ;cat, \|bash, ;wget, ;curl, backtick execution, etc. |
| **Scanner** | nikto, sqlmap, nmap, masscan, acunetix, nessus, etc. |
| **Sensitive File Probe** | .git, .env, .htaccess, backup, phpmyadmin, etc. |
| **Webshell** | cmd.php, shell.php, eval(), base64_decode(), system(), etc. |
| **Vulnerability Probe** | autodiscover, owa, thinkphp, jndi:, ldap:, rmi:, etc. |
| **Protocol Attack** | Hex encoding, CONNECT method, etc. |
| **Proxy Attack** | GET http://, POST http://, CONNECT IP:port, etc. |
| **AI API Probe** | /v1/models, /v1/chat/completions, /v1/embeddings, etc. (AI API scanning) |

### Upgrade

```bash
# Interactive upgrade
./install.sh

# Non-interactive upgrade (merge config by default)
./install.sh --upgrade

# Specify language
./install.sh --lang en
./install.sh --lang en --upgrade
```

**Config handling options:**

| Option | Description | Use case |
|--------|-------------|----------|
| Overwrite | Use new default config | Few customizations, want new defaults |
| Keep | Preserve old config | Many customizations, handle new options manually |
| Merge | Keep custom values + add new options | Recommended, best of both |

### Configuration

Edit `/etc/ip-ban-hammer/security.conf`:

```ini
[paths]
# Log files (comma-separated for multiple)
log_files = /var/log/nginx/access.log
# Data files
pending = /var/lib/ip-ban-hammer/pending.list
applied = /var/lib/ip-ban-hammer/applied.list
allow = /etc/ip-ban-hammer/allow.list
# Log files
main_log = /var/log/ip-ban-hammer/main.log
history = /var/log/ip-ban-hammer/history.log
stats = /var/log/ip-ban-hammer/stats.log

[iptables]
# iptables chain name (change if conflicts with other tools)
chain_name = IP_BAN_HAMMER

[thresholds]
# Number of attacks to trigger ban
attack_threshold = 5
# Time window for attack counting (minutes)
time_window_minutes = 30
# Days to keep ban history
days_to_keep = 30
# File size threshold for reverse reading (MB)
reverse_read_threshold_mb = 100

[cron]
# Log analysis frequency (match or shorter than time_window_minutes)
analyze_cron = */30 * * * *
# Ban application frequency (keep every minute for timely blocking)
apply_cron = * * * * *
# Cleanup schedule (default: daily at 3:00 AM)
cleanup_cron = 0 3 * * *

[general]
# Language: zh (Chinese) or en (English)
language = en
# Enable colored output: true or false
color_output = true

[security]
# Skip private/reserved IP addresses from banning
# Includes: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, etc.
skip_private_ip = true
# IP position detection: auto, first, forwarded, json, custom
log_ip_position = auto
# json_ip_key = remote_addr     # key name for json mode
# custom_ip_regex =             # regex for custom mode

[alert]
# Alert notification configuration (optional)
# Choose webhook OR email (webhook takes priority)

# Webhook URL (HTTP POST notification)
# webhook_url = https://hooks.slack.com/services/XXX/YYY/ZZZ
# webhook_url = 

# Email recipient (requires mail/sendmail command)
# email_to = admin@example.com

# Email sender (optional)
# email_sender = ipban-noreply@example.com
```

**Config example files:**
- Source package: `config/security.conf.example`, `config/allow.list.example`
- Copied to: `/opt/ip-ban-hammer/config/` for reference
- Runtime config: `/etc/ip-ban-hammer/` (edit files here to take effect)

### Whitelist

Supports both single IP and CIDR notation.

Edit `/etc/ip-ban-hammer/allow.list`:

```
# IP Ban Hammer Allow List
# One IP or CIDR per line, # for comments

# Single IPs
127.0.0.1
192.168.1.100

# CIDR ranges
10.0.0.0/8           # Private network 10.x.x.x
172.16.0.0/12        # Private network 172.16-31.x.x
192.168.0.0/16       # Private network 192.168.x.x

# Search engine IP ranges (optional)
66.249.64.0/19       # Google
123.125.0.0/16       # Baidu
220.181.0.0/16       # Baidu
```

**Auto-detected during installation:**
- Private IPs: 127.0.0.1, all IPs from `hostname -I`
- Public IP: fetched via ifconfig.me / ip.sb / icanhazip.com

### Management Commands

```bash
# Show help
ipban --help
ipban -h                    # short flag
ipban help status           # help for specific command

# Show version
ipban version
ipban -V                    # short flag

# Show status
ipban status

# List all banned IPs
ipban list

# Manually ban IP
ipban ban 1.2.3.4
ipban ban 1.2.3.4 "SQL injection attack"  # with reason

# Unban IP
ipban unban 1.2.3.4

# Remove all bans
ipban flush

# Cleanup history
ipban cleanup 30

# Whitelist management (supports IP and CIDR)
ipban whitelist
ipban wl                    # short alias
ipban whitelist add 1.2.3.4
ipban whitelist add 10.0.0.0/8   # add CIDR range
ipban wl del 1.2.3.4

# Analyze logs
ipban analyze --full              # Full analysis
ipban analyze --days 7            # Last 7 days
ipban analyze --days 7 --threshold 10  # Custom threshold
ipban analyze --preview           # Preview mode (don't write to files)

# Apply bans (dry-run mode)
/opt/ip-ban-hammer/bin/apply_iptables_ban.sh --dry-run

# Statistics
ipban stats

# View logs
ipban logs
ipban logs 50  # Last 50 lines

# Config management
ipban config                          # Show full config
ipban config get thresholds.attack_threshold  # Get config value
ipban config set thresholds.attack_threshold 10  # Set config value
ipban config edit                     # Edit config in editor
ipban config backup                   # Manual config backup
ipban config backups                  # List config backups
ipban config restore 1                # Restore to backup #1

# System check
ipban check
```

### Cron Jobs / Systemd

**Option 1: cron (default)**

Auto-configured after installation (`/etc/cron.d/ip-ban-hammer`):
- Every 30 minutes: Analyze logs (configurable via advanced settings)
- Every minute: Apply ban rules
- Daily at 3:00 AM: Cleanup history (configurable via advanced settings)

**Option 2: systemd (optional)**

If systemd is detected during installation, you can choose systemd timers:
```bash
# Check timer status
systemctl list-timers | grep ipban

# Manually trigger analysis
systemctl start ipban-analyze.service

# Manually trigger ban application
systemctl start ipban-apply.service
```

### Uninstall

```bash
/opt/ip-ban-hammer/bin/uninstall.sh
```

**Files preserved during uninstall (remove manually if needed):**
- Config files: `/etc/ip-ban-hammer/`
- Data files: `/var/lib/ip-ban-hammer/`
- Log files: `/var/log/ip-ban-hammer/`

### Directory Structure

```
/opt/ip-ban-hammer/               # Scripts
├── bin/
│   ├── auto_ban_attacks.py      # Log analyzer - scheduled
│   ├── full_scan.py             # Full scan - manual
│   ├── apply_iptables_ban.sh    # Apply iptables rules
│   ├── ban_manager.sh           # Management tool
│   └── uninstall.sh             # Uninstall script
├── config/
│   ├── security.conf.example    # Config example
│   └── allow.list.example       # Whitelist example
├── lib/
│   ├── ipban_core/              # Shared module library
│   │   ├── __init__.py          # Module entry
│   │   ├── patterns.py          # Attack patterns
│   │   ├── validators.py        # IP/CIDR validation
│   │   ├── config.py            # Config loading
│   │   ├── whitelist.py         # Whitelist handling
│   │   ├── alert.py             # Alert notifications
│   │   ├── migration.py         # Config migration
│   │   ├── backup.py            # Backup & rollback
│   │   └── log_parser.py        # Log parsing
│   └── completion/
│       └── ipban.bash            # Bash completion
└── systemd/                      # systemd service files (optional)
    ├── ipban-analyze.service
    ├── ipban-analyze.timer
    ├── ipban-apply.service
    ├── ipban-apply.timer
    ├── ipban-cleanup.service
    └── ipban-cleanup.timer

/etc/ip-ban-hammer/               # Runtime config
├── security.conf                # Runtime config (edit this)
├── allow.list                   # Whitelist
└── i18n/
    └── en.lang                  # Language file

/var/lib/ip-ban-hammer/           # Data files
├── pending.list                 # Pending bans
├── applied.list                 # Applied bans
├── config_backups/              # Config backup directory
│   ├── security.conf.YYYYMMDD_HHMMSS  # Config backup files
│   └── backup_history.log      # Backup history
└── backups/                     # iptables backup directory
    └── backup_YYYYMMDD_HHMMSS/  # Backup files

/var/log/ip-ban-hammer/           # Log files
├── main.log                     # Runtime log
├── history.log                  # Ban history
├── stats.log                    # Statistics
└── ipv6_detected.log            # IPv6 detection log
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| `python3: command not found` | Install Python 3: `apt install python3` |
| `iptables: command not found` | Install iptables: `apt install iptables` |
| Permission denied | Run as root or with sudo |
| Cron not running | Check: `cat /etc/cron.d/ip-ban-hammer` |
| Bans not applied | Check: `iptables -n -L IP_BAN_HAMMER` |

## License

MIT License
