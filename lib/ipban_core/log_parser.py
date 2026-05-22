"""
Log parsing utilities for IP Ban Hammer.

Shared between auto_ban_attacks.py and full_scan.py.
"""

import re
import os
import json
import logging
from datetime import datetime
from . import validators

logger = logging.getLogger(__name__)


def extract_ip_from_line(line, log_ip_position='auto', json_ip_key='remote_addr', custom_ip_regex=''):
    """
    Extract IP address from log line based on configured method.
    
    Args:
        line: Log line string
        log_ip_position: Extraction method ('auto', 'first', 'forwarded', 'json', 'custom')
        json_ip_key: Key name for JSON format
        custom_ip_regex: Custom regex pattern
        
    Returns:
        IP address string or None
    """
    if log_ip_position == 'first':
        ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
        return ip_match.group(1) if ip_match else None
    
    elif log_ip_position == 'forwarded':
        forwarded_match = re.search(r'X-Forwarded-For:\s*([^\]]+)', line, re.IGNORECASE)
        if forwarded_match:
            forwarded_value = forwarded_match.group(1).strip()
            ips = [ip.strip() for ip in forwarded_value.split(',') if ip.strip()]
            if ips:
                return ips[-1]
        ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
        return ip_match.group(1) if ip_match else None
    
    elif log_ip_position == 'json':
        try:
            data = json.loads(line)
            return data.get(json_ip_key)
        except (json.JSONDecodeError, KeyError):
            return None
    
    elif log_ip_position == 'custom' and custom_ip_regex:
        try:
            custom_match = re.search(custom_ip_regex, line)
            if custom_match:
                return custom_match.group(1)
        except re.error:
            logger.warning(f"Invalid custom IP regex: {custom_ip_regex}")
        return None
    
    elif log_ip_position == 'auto':
        # 1. Try line start (standard NCSA format)
        ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            return ip_match.group(1)
        
        # 2. Try JSON format
        if line.startswith('{'):
            try:
                data = json.loads(line)
                for key in ['remote_addr', 'client_ip', 'ip', 'source_ip', 'src_ip']:
                    if key in data:
                        return data[key]
            except json.JSONDecodeError:
                pass
        
        # 3. Try X-Forwarded-For
        forwarded_match = re.search(r'X-Forwarded-For:\s*([^\]]+)', line, re.IGNORECASE)
        if forwarded_match:
            forwarded_value = forwarded_match.group(1).strip()
            ips = [ip.strip() for ip in forwarded_value.split(',') if ip.strip()]
            if ips:
                return ips[-1]
        
        # 4. Fallback: search first IP pattern in line
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        return ip_match.group(1) if ip_match else None
    
    return None


def extract_ipv6_from_line(line):
    """
    Extract IPv6 address from log line.
    
    Args:
        line: Log line string
        
    Returns:
        IPv6 address string or None
    """
    ipv6_patterns = [
        r'([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})',
        r'([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)',
        r'(::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)',
        r'((?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?::)',
    ]
    for pattern in ipv6_patterns:
        match = re.search(pattern, line)
        if match:
            ip = match.group(1)
            if validators.is_ipv6(ip):
                return ip
    return None


def log_ipv6_detection(ip, attack_type, ipv6_file):
    """
    Log IPv6 address detection to dedicated file.
    
    Args:
        ip: IPv6 address
        attack_type: Attack type detected
        ipv6_file: Path to IPv6 detection log file
    """
    try:
        os.makedirs(os.path.dirname(ipv6_file), exist_ok=True)
        with open(ipv6_file, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {ip} | {attack_type}\n")
    except IOError as e:
        logger.error(f"Failed to write IPv6 detection log: {e}")
