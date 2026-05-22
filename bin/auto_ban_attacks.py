#!/usr/bin/env python3
import re
import os
import sys
import logging
import argparse
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))
from ipban_core import patterns, validators, config, whitelist, alert, log_parser

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

if sys.version_info >= (3, 7):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception as e:
        logger.warning(f"Failed to reconfigure stdout encoding: {e}")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = config.get_config_path(SCRIPT_DIR)

def load_lang(lang='zh'):
    i18n_dir = '/etc/ip-ban-hammer/i18n'
    if not os.path.exists(i18n_dir):
        i18n_dir = os.path.join(os.path.dirname(SCRIPT_DIR), 'config', 'i18n')
    
    translations = {}
    i18n_file = os.path.join(i18n_dir, f'{lang}.lang')
    if not os.path.exists(i18n_file):
        return translations
    
    with open(i18n_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                translations[key.strip()] = value.strip()
    return translations

def get_text(key, translations, default=None):
    return translations.get(key, default or key)

cfg = config.load_config(CONFIG_FILE)
lang = config.get_language(cfg)
TRANSLATIONS = load_lang(lang)

LOG_FILES_STR = config.get_path(cfg, 'log_files', '/www/wwwlogs/www.log')
LOG_FILES = [f.strip() for f in LOG_FILES_STR.split(',') if f.strip()]

PENDING_FILE = config.get_path(cfg, 'pending', '/var/lib/ip-ban-hammer/pending.list')
HISTORY_FILE = config.get_path(cfg, 'history', '/var/log/ip-ban-hammer/history.log')
STATS_FILE = config.get_path(cfg, 'stats', '/var/log/ip-ban-hammer/stats.log')
ALLOW_FILE = config.get_path(cfg, 'allow', '/etc/ip-ban-hammer/allow.list')
IPv6_DETECTED_FILE = '/var/log/ip-ban-hammer/ipv6_detected.log'

ATTACK_THRESHOLD = config.get_int(cfg, 'thresholds', 'attack_threshold', 5)
TIME_WINDOW_MINUTES = config.get_int(cfg, 'thresholds', 'time_window_minutes', 30)
REVERSE_READ_THRESHOLD_MB = config.get_int(cfg, 'thresholds', 'reverse_read_threshold_mb', 100)
SKIP_PRIVATE_IP = config.get_bool(cfg, 'security', 'skip_private_ip', True)

LOG_IP_POSITION = config.get_str(cfg, 'security', 'log_ip_position', 'auto')
JSON_IP_KEY = config.get_str(cfg, 'security', 'json_ip_key', 'remote_addr')
CUSTOM_IP_REGEX = config.get_str(cfg, 'security', 'custom_ip_regex', '')

ALERT_CONFIG = {
    'webhook_url': config.get_str(cfg, 'alert', 'webhook_url', ''),
    'email_to': config.get_str(cfg, 'alert', 'email_to', ''),
    'email_sender': config.get_str(cfg, 'alert', 'email_sender', ''),
}
HOSTNAME = os.uname().nodename if hasattr(os, 'uname') else os.environ.get('HOSTNAME', 'unknown')

MAX_LINES_TO_SCAN = 500000

WHITELIST_SINGLE, WHITELIST_CIDR = whitelist.load_whitelist(ALLOW_FILE)

MONTH_MAP = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

def parse_log_date(line):
    match = re.search(r'\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})', line)
    if match:
        day, month_str, year, hour, minute, second = match.groups()
        month = MONTH_MAP.get(month_str, 0)
        if month:
            try:
                return datetime(int(year), month, int(day), int(hour), int(minute), int(second))
            except (ValueError, OverflowError) as e:
                logger.debug(f"Failed to parse date from line: {e}")
    return None

def load_existing_bans():
    existing = set()
    if os.path.exists(PENDING_FILE):
        try:
            with open(PENDING_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    ip = line.strip().split('#')[0].strip()
                    if ip and validators.validate_ip(ip):
                        existing.add(ip)
                    elif ip:
                        logger.warning(f"Invalid IP in ban list file, skipping: {ip}")
        except IOError as e:
            logger.error(f"Failed to read ban list file {PENDING_FILE}: {e}")
    return existing

def get_file_size_mb(filepath):
    return os.path.getsize(filepath) / (1024 * 1024)

def check_log_file_sizes():
    """Check log file sizes and warn if they exceed threshold."""
    warning_threshold_mb = 50
    files_to_check = [
        ('history.log', HISTORY_FILE),
        ('stats.log', STATS_FILE),
        ('applied.list', config.get_path(cfg, 'applied', '/var/lib/ip-ban-hammer/applied.list')),
    ]
    
    for name, filepath in files_to_check:
        if os.path.exists(filepath):
            size_mb = get_file_size_mb(filepath)
            if size_mb > warning_threshold_mb:
                logger.warning(f"{name} size ({size_mb:.1f}MB) exceeds threshold ({warning_threshold_mb}MB), consider cleanup")

def read_lines_reverse(filepath, max_lines):
    """Read file in reverse order using Python native method (memory efficient)."""
    lines = []
    try:
        with open(filepath, 'rb') as f:
            f.seek(0, 2)
            file_size = f.tell()
            
            if file_size == 0:
                return []
            
            chunk_size = 8192
            pos = file_size
            buffer = b''
            
            while pos > 0 and len(lines) < max_lines:
                read_size = min(chunk_size, pos)
                pos -= read_size
                f.seek(pos)
                chunk = f.read(read_size)
                buffer = chunk + buffer
                
                while b'\n' in buffer and len(lines) < max_lines:
                    idx = buffer.rfind(b'\n')
                    line = buffer[idx+1:].decode('utf-8', errors='ignore').strip()
                    if line:
                        lines.append(line)
                    buffer = buffer[:idx]
            
            if buffer and len(lines) < max_lines:
                line = buffer.decode('utf-8', errors='ignore').strip()
                if line:
                    lines.append(line)
        
        return lines[:max_lines]
    except IOError as e:
        logger.warning(f"Error reading file {filepath} in reverse: {e}")
        return []
    except Exception as e:
        logger.warning(f"Unexpected error reading {filepath}: {e}")
        return []

def analyze_log_file_optimized(log_file, time_threshold, ip_attack_count, whitelist_single, whitelist_cidr, translations):
    total_lines = 0
    attack_lines = 0
    recent_lines = 0
    skipped = 0
    private_skipped = 0
    ipv6_detected = 0
    lines_scanned = 0
    early_stopped = False
    
    if not os.path.exists(log_file):
        return total_lines, attack_lines, recent_lines, skipped, private_skipped, ipv6_detected, lines_scanned, early_stopped
    
    file_size_mb = get_file_size_mb(log_file)
    print(f"    {get_text('analyzer.file_size', translations)}: {file_size_mb:.2f} MB")
    
    use_reverse = file_size_mb > REVERSE_READ_THRESHOLD_MB
    
    if use_reverse:
        print(f"    {get_text('analyzer.using_optimization', translations)}")
        lines = read_lines_reverse(log_file, MAX_LINES_TO_SCAN)
        
        for line in lines:
            lines_scanned += 1
            line = line.strip()
            if not line:
                continue
            
            log_date = parse_log_date(line)
            if log_date is None:
                continue
            
            if log_date < time_threshold:
                early_stopped = True
                break
            
            recent_lines += 1
            
            attack_type = patterns.detect_attack(line)
            if attack_type:
                attack_lines += 1
                ip = log_parser.extract_ip_from_line(line, LOG_IP_POSITION, JSON_IP_KEY, CUSTOM_IP_REGEX)
                if ip:
                    if not validators.validate_ip(ip):
                        ipv6 = log_parser.extract_ipv6_from_line(line)
                        if ipv6:
                            ipv6_detected += 1
                            log_parser.log_ipv6_detection(ipv6, attack_type, IPv6_DETECTED_FILE)
                            logger.warning(f"IPv6 address detected but not supported: {ipv6}, logged to ipv6_detected.log")
                        continue
                    if SKIP_PRIVATE_IP and validators.is_private_ip(ip):
                        private_skipped += 1
                        continue
                    if validators.is_in_whitelist(ip, whitelist_single, whitelist_cidr):
                        skipped += 1
                        continue
                    ip_attack_count[ip]['count'] += 1
                    ip_attack_count[ip]['types'].add(attack_type)
    else:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                total_lines += 1
                lines_scanned += 1
                line = line.strip()
                if not line:
                    continue
                
                log_date = parse_log_date(line)
                if log_date is None:
                    continue
                
                if log_date < time_threshold:
                    continue
                
                recent_lines += 1
                
                attack_type = patterns.detect_attack(line)
                if attack_type:
                    attack_lines += 1
                    ip = log_parser.extract_ip_from_line(line, LOG_IP_POSITION, JSON_IP_KEY, CUSTOM_IP_REGEX)
                    if ip:
                        if not validators.validate_ip(ip):
                            ipv6 = log_parser.extract_ipv6_from_line(line)
                            if ipv6:
                                ipv6_detected += 1
                                log_parser.log_ipv6_detection(ipv6, attack_type, IPv6_DETECTED_FILE)
                                logger.warning(f"IPv6 address detected but not supported: {ipv6}, logged to ipv6_detected.log")
                            continue
                        if SKIP_PRIVATE_IP and validators.is_private_ip(ip):
                            private_skipped += 1
                            continue
                        if validators.is_in_whitelist(ip, whitelist_single, whitelist_cidr):
                            skipped += 1
                            continue
                        ip_attack_count[ip]['count'] += 1
                        ip_attack_count[ip]['types'].add(attack_type)
    
    return total_lines, attack_lines, recent_lines, skipped, private_skipped, ipv6_detected, lines_scanned, early_stopped

def main():
    parser = argparse.ArgumentParser(description='Auto ban attack IPs')
    parser.add_argument('--preview', '-p', action='store_true', help='Preview mode - show IPs without writing to files')
    args = parser.parse_args()
    
    start_time = datetime.now()
    time_threshold = start_time - timedelta(minutes=TIME_WINDOW_MINUTES)
    
    if args.preview:
        print(f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] {get_text('analyzer.start', TRANSLATIONS)} ({get_text('analyzer.preview_mode', TRANSLATIONS)})")
    else:
        print(f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] {get_text('analyzer.start', TRANSLATIONS)}")
    print(f"  {get_text('analyzer.config_file', TRANSLATIONS)}: {CONFIG_FILE}")
    print(f"  {get_text('analyzer.log_file', TRANSLATIONS)}: {LOG_FILES_STR}")
    print(f"  {get_text('analyzer.time_window', TRANSLATIONS).format(TIME_WINDOW_MINUTES)}")
    print(f"  {get_text('analyzer.attack_threshold', TRANSLATIONS).format(ATTACK_THRESHOLD)}")
    print(f"  {get_text('analyzer.whitelist_file', TRANSLATIONS)}: {ALLOW_FILE}")
    
    whitelist_count = whitelist.get_whitelist_count(WHITELIST_SINGLE, WHITELIST_CIDR)
    if whitelist_count > 0:
        display_str = whitelist.format_whitelist_display(WHITELIST_SINGLE, WHITELIST_CIDR)
        print(f"  {get_text('analyzer.whitelist_ips', TRANSLATIONS)}: {display_str}")
    
    if not args.preview:
        os.makedirs(os.path.dirname(PENDING_FILE), exist_ok=True)
    
    check_log_file_sizes()
    
    ip_attack_count = defaultdict(lambda: {'count': 0, 'types': set()})
    total_lines = 0
    attack_lines = 0
    recent_lines = 0
    total_skipped = 0
    total_private_skipped = 0
    total_ipv6_detected = 0
    total_scanned = 0
    
    for log_file in LOG_FILES:
        if not os.path.exists(log_file):
            print(f"  {get_text('analyzer.log_not_exist', TRANSLATIONS)}: {log_file}")
            continue
        
        print(f"  {get_text('analyzer.analyzing', TRANSLATIONS)}: {log_file}")
        t, a, r, s, ps, ipv6, scanned, early_stop = analyze_log_file_optimized(
            log_file, time_threshold, ip_attack_count, WHITELIST_SINGLE, WHITELIST_CIDR, TRANSLATIONS
        )
        total_lines += t
        attack_lines += a
        recent_lines += r
        total_skipped += s
        total_private_skipped += ps
        total_ipv6_detected += ipv6
        total_scanned += scanned
        
        if early_stop:
            print(f"    {get_text('analyzer.early_stop', TRANSLATIONS)}")
        print(f"    {get_text('analyzer.lines_scanned', TRANSLATIONS)}: {scanned:,}")
    
    print(f"  {get_text('analyzer.recent_lines', TRANSLATIONS).format(TIME_WINDOW_MINUTES)}: {recent_lines:,}")
    print(f"  {get_text('analyzer.attack_requests', TRANSLATIONS)}: {attack_lines:,}")
    if total_skipped > 0:
        print(f"  {get_text('analyzer.skipped_whitelist', TRANSLATIONS)}: {total_skipped:,}")
    if total_private_skipped > 0:
        print(f"  {get_text('analyzer.skipped_private', TRANSLATIONS)}: {total_private_skipped:,}")
    if total_ipv6_detected > 0:
        print(f"  {get_text('analyzer.ipv6_detected', TRANSLATIONS)}: {total_ipv6_detected:,}")
    
    existing_bans = load_existing_bans()
    new_bans = []
    
    for ip, data in ip_attack_count.items():
        if data['count'] >= ATTACK_THRESHOLD and ip not in existing_bans:
            new_bans.append((ip, data['count'], data['types']))
    
    new_bans.sort(key=lambda x: x[1], reverse=True)
    
    if new_bans:
        print(f"\n{get_text('analyzer.found_new_bans', TRANSLATIONS).format(len(new_bans))}")
        for ip, count, types in new_bans[:20]:
            types_str = ", ".join(sorted(types)[:3])
            print(f"  {ip:<18} {count:>5} {get_text('analyzer.times', TRANSLATIONS)}  [{types_str}]")
        if len(new_bans) > 20:
            print(f"  ... {get_text('analyzer.more_ips', TRANSLATIONS).format(len(new_bans)-20)}")
        
        if not args.preview:
            try:
                with open(PENDING_FILE, 'a', encoding='utf-8') as f:
                    for ip, count, types in new_bans:
                        types_str = ",".join(sorted(types))
                        f.write(f"{ip} # {start_time.strftime('%Y-%m-%d %H:%M:%S')} {count}{get_text('analyzer.times', TRANSLATIONS)} [{types_str}]\n")
            except IOError as e:
                logger.error(f"Failed to write to ban list file {PENDING_FILE}: {e}")
            
            try:
                with open(HISTORY_FILE, 'a', encoding='utf-8') as f:
                    for ip, count, types in new_bans:
                        types_str = ",".join(sorted(types))
                        f.write(f"{start_time.strftime('%Y-%m-%d %H:%M:%S')} | {ip} | {count} | {types_str}\n")
            except IOError as e:
                logger.error(f"Failed to write to ban history file {HISTORY_FILE}: {e}")
            
            if ALERT_CONFIG.get('webhook_url') or ALERT_CONFIG.get('email_to'):
                print(f"\n{get_text('analyzer.sending_alerts', TRANSLATIONS)}")
                for ip, count, types in new_bans[:10]:
                    success, msg = alert.send_alert(ALERT_CONFIG, ip, count, types, HOSTNAME, lang)
                    if not success:
                        logger.warning(f"Alert failed for {ip}: {msg}")
            
            print(f"\n{get_text('analyzer.written_to', TRANSLATIONS)}: {PENDING_FILE}")
        else:
            print(f"\n{get_text('analyzer.preview_would_write', TRANSLATIONS).format(len(new_bans), PENDING_FILE)}")
    else:
        print(f"\n{get_text('analyzer.no_new_bans', TRANSLATIONS)}")
    
    elapsed = (datetime.now() - start_time).total_seconds()
    
    if not args.preview:
        try:
            with open(STATS_FILE, 'a', encoding='utf-8') as f:
                f.write(f"{start_time.strftime('%Y-%m-%d %H:%M:%S')} | scanned={total_scanned} | recent={recent_lines} | attacks={attack_lines} | new_bans={len(new_bans)} | elapsed={elapsed:.2f}s\n")
        except IOError as e:
            logger.error(f"Failed to write to stats file {STATS_FILE}: {e}")
    
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {get_text('analyzer.complete', TRANSLATIONS)} ({get_text('analyzer.elapsed_time', TRANSLATIONS).format(elapsed)})")

if __name__ == '__main__':
    main()
