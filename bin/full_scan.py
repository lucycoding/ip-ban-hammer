#!/usr/bin/env python3
import re
import os
import sys
import argparse
import subprocess
import logging
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))
from ipban_core import patterns, validators, config, whitelist, log_parser

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
translations = load_lang(lang)

LOG_FILES_STR = config.get_path(cfg, 'log_files', '/www/wwwlogs/www.log')
LOG_FILES = [f.strip() for f in LOG_FILES_STR.split(',') if f.strip()]

PENDING_FILE = config.get_path(cfg, 'pending', '/var/lib/ip-ban-hammer/pending.list')
HISTORY_FILE = config.get_path(cfg, 'history', '/var/log/ip-ban-hammer/history.log')
STATS_FILE = config.get_path(cfg, 'stats', '/var/log/ip-ban-hammer/stats.log')
ALLOW_FILE = config.get_path(cfg, 'allow', '/etc/ip-ban-hammer/allow.list')
IPv6_DETECTED_FILE = '/var/log/ip-ban-hammer/ipv6_detected.log'

DEFAULT_THRESHOLD = config.get_int(cfg, 'thresholds', 'attack_threshold', 5)
SKIP_PRIVATE_IP = config.get_bool(cfg, 'security', 'skip_private_ip', True)

LOG_IP_POSITION = config.get_str(cfg, 'security', 'log_ip_position', 'auto')
JSON_IP_KEY = config.get_str(cfg, 'security', 'json_ip_key', 'remote_addr')
CUSTOM_IP_REGEX = config.get_str(cfg, 'security', 'custom_ip_regex', '')

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

def get_line_count(filepath):
    try:
        result = subprocess.run(
            ['wc', '-l', filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        return int(result.stdout.split()[0])
    except Exception:
        return 0

def show_progress(current, total, prefix='Progress'):
    if total <= 0:
        return
    bar_length = 40
    percent = current / total * 100
    filled = int(bar_length * current / total)
    bar = '#' * filled + '-' * (bar_length - filled)
    print(f"\r{prefix}: |{bar}| {current:,}/{total:,} ({percent:.1f}%)", end='', flush=True)
    if current >= total:
        print()

def analyze_log_file(log_file, time_threshold, ip_attack_count, whitelist_single, whitelist_cidr, translations):
    total_lines = 0
    attack_lines = 0
    skipped = 0
    private_skipped = 0
    ipv6_detected = 0
    
    if not os.path.exists(log_file):
        return total_lines, attack_lines, skipped, private_skipped, ipv6_detected
    
    file_size_mb = get_file_size_mb(log_file)
    file_line_count = get_line_count(log_file)
    
    print(f"    {get_text('analyzer.file_size', translations)}: {file_size_mb:.2f} MB")
    print(f"    {get_text('analyzer.total_lines', translations)}: {file_line_count:,}")
    
    processed = 0
    progress_interval = 10000
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            processed += 1
            total_lines += 1
            line = line.strip()
            if not line:
                continue
            
            if processed % progress_interval == 0:
                show_progress(processed, file_line_count, f"    {get_text('analyzer.progress', translations)}")
            
            log_date = parse_log_date(line)
            if log_date is None:
                continue
            
            if time_threshold and log_date < time_threshold:
                continue
            
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
    
    show_progress(file_line_count, file_line_count, f"    {get_text('analyzer.progress', translations)}")
    
    return total_lines, attack_lines, skipped, private_skipped, ipv6_detected

def main():
    parser = argparse.ArgumentParser(description='Full log analysis')
    parser.add_argument('--full', '-f', action='store_true', help='Full analysis (all logs)')
    parser.add_argument('--days', '-d', type=int, help='Analyze last N days')
    parser.add_argument('--threshold', '-t', type=int, default=DEFAULT_THRESHOLD, help='Ban threshold')
    parser.add_argument('--preview', '-p', action='store_true', help='Preview mode - show IPs without writing to files')
    args = parser.parse_args()
    
    start_time = datetime.now()
    
    if args.days:
        time_threshold = start_time - timedelta(days=args.days)
    else:
        time_threshold = None
    
    if args.preview:
        print(f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] {get_text('analyzer.start_full', translations)} ({get_text('analyzer.preview_mode', translations)})")
    else:
        print(f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] {get_text('analyzer.start_full', translations)}")
    print(f"  {get_text('analyzer.config_file', translations)}: {CONFIG_FILE}")
    print(f"  {get_text('analyzer.log_file', translations)}: {LOG_FILES_STR}")
    
    if time_threshold:
        print(f"  {get_text('analyzer.mode_days', translations).format(args.days)}")
    else:
        print(f"  {get_text('analyzer.mode_full', translations)}")
    
    print(f"  {get_text('analyzer.attack_threshold', translations).format(args.threshold)}")
    print(f"  {get_text('analyzer.whitelist_file', translations)}: {ALLOW_FILE}")
    
    whitelist_single, whitelist_cidr = whitelist.load_whitelist(ALLOW_FILE)
    whitelist_count = whitelist.get_whitelist_count(whitelist_single, whitelist_cidr)
    if whitelist_count > 0:
        display_str = whitelist.format_whitelist_display(whitelist_single, whitelist_cidr)
        print(f"  {get_text('analyzer.whitelist_ips', translations)}: {display_str}")
    
    if not args.preview:
        os.makedirs(os.path.dirname(PENDING_FILE), exist_ok=True)
    
    ip_attack_count = defaultdict(lambda: {'count': 0, 'types': set()})
    total_lines = 0
    attack_lines = 0
    total_skipped = 0
    total_private_skipped = 0
    total_ipv6_detected = 0
    
    for log_file in LOG_FILES:
        if not os.path.exists(log_file):
            print(f"  {get_text('analyzer.log_not_exist', translations)}: {log_file}")
            continue
        
        print(f"  {get_text('analyzer.analyzing', translations)}: {log_file}")
        t, a, s, ps, ipv6 = analyze_log_file(log_file, time_threshold, ip_attack_count, whitelist_single, whitelist_cidr, translations)
        total_lines += t
        attack_lines += a
        total_skipped += s
        total_private_skipped += ps
        total_ipv6_detected += ipv6
    
    print(f"\n  {get_text('analyzer.total_lines', translations)}: {total_lines:,}")
    print(f"  {get_text('analyzer.attack_requests', translations)}: {attack_lines:,}")
    if total_skipped > 0:
        print(f"  {get_text('analyzer.skipped_whitelist', translations)}: {total_skipped:,}")
    if total_private_skipped > 0:
        print(f"  {get_text('analyzer.skipped_private', translations)}: {total_private_skipped:,}")
    if total_ipv6_detected > 0:
        print(f"  {get_text('analyzer.ipv6_detected', translations)}: {total_ipv6_detected:,}")
    
    existing_bans = load_existing_bans()
    new_bans = []
    
    for ip, data in ip_attack_count.items():
        if data['count'] >= args.threshold and ip not in existing_bans:
            new_bans.append((ip, data['count'], data['types']))
    
    new_bans.sort(key=lambda x: x[1], reverse=True)
    
    if new_bans:
        print(f"\n{get_text('analyzer.found_new_bans', translations).format(len(new_bans))}")
        for ip, count, types in new_bans[:20]:
            types_str = ", ".join(sorted(types)[:3])
            print(f"  {ip:<18} {count:>5} {get_text('analyzer.times', translations)}  [{types_str}]")
        if len(new_bans) > 20:
            print(f"  ... {get_text('analyzer.more_ips', translations).format(len(new_bans)-20)}")
        
        if not args.preview:
            try:
                with open(PENDING_FILE, 'a', encoding='utf-8') as f:
                    for ip, count, types in new_bans:
                        types_str = ",".join(sorted(types))
                        f.write(f"{ip} # {start_time.strftime('%Y-%m-%d %H:%M:%S')} {count}{get_text('analyzer.times', translations)} [{types_str}]\n")
            except IOError as e:
                logger.error(f"Failed to write to ban list file {PENDING_FILE}: {e}")
            
            try:
                with open(HISTORY_FILE, 'a', encoding='utf-8') as f:
                    for ip, count, types in new_bans:
                        types_str = ",".join(sorted(types))
                        f.write(f"{start_time.strftime('%Y-%m-%d %H:%M:%S')} | {ip} | {count} | {types_str}\n")
            except IOError as e:
                logger.error(f"Failed to write to ban history file {HISTORY_FILE}: {e}")
            
            print(f"\n{get_text('analyzer.written_to', translations)}: {PENDING_FILE}")
        else:
            print(f"\n{get_text('analyzer.preview_would_write', translations).format(len(new_bans), PENDING_FILE)}")
    else:
        print(f"\n{get_text('analyzer.no_new_bans', translations)}")
    
    elapsed = (datetime.now() - start_time).total_seconds()
    
    if not args.preview:
        try:
            with open(STATS_FILE, 'a', encoding='utf-8') as f:
                mode = f"days={args.days}" if args.days else "full"
                f.write(f"{start_time.strftime('%Y-%m-%d %H:%M:%S')} | mode={mode} | scanned={total_lines} | attacks={attack_lines} | new_bans={len(new_bans)} | elapsed={elapsed:.2f}s\n")
        except IOError as e:
            logger.error(f"Failed to write to stats file {STATS_FILE}: {e}")
    
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {get_text('analyzer.complete', translations)} ({get_text('analyzer.elapsed_time', translations).format(elapsed)})")

if __name__ == '__main__':
    main()
