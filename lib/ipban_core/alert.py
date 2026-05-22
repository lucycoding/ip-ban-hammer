"""
Alert notification utilities for IP Ban Hammer.

Provides:
- Webhook notifications (generic HTTP POST)
- Email notifications (via sendmail/mail command)
- Connectivity checking
"""

import os
import json
import subprocess
import logging
import urllib.request
import urllib.error
from datetime import datetime

logger = logging.getLogger(__name__)


def check_webhook_connectivity(webhook_url, timeout=5):
    """
    Check if webhook URL is reachable.
    
    Args:
        webhook_url: Webhook URL to check
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    if not webhook_url:
        return False, "Webhook URL is empty"
    
    try:
        req = urllib.request.Request(webhook_url, method='HEAD')
        urllib.request.urlopen(req, timeout=timeout)
        return True, "Webhook is reachable"
    except urllib.error.URLError as e:
        return False, f"Webhook unreachable: {e}"
    except Exception as e:
        return False, f"Webhook check failed: {e}"


def send_webhook_alert(webhook_url, data, timeout=10):
    """
    Send alert via webhook.
    
    Args:
        webhook_url: Webhook URL
        data: Dictionary of data to send
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    if not webhook_url:
        return False, "Webhook URL is empty"
    
    try:
        json_data = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(
            webhook_url,
            data=json_data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        response = urllib.request.urlopen(req, timeout=timeout)
        if response.status >= 200 and response.status < 300:
            return True, f"Alert sent successfully (HTTP {response.status})"
        else:
            return False, f"Webhook returned HTTP {response.status}"
    except urllib.error.URLError as e:
        return False, f"Failed to send webhook: {e}"
    except Exception as e:
        return False, f"Webhook error: {e}"


def check_email_command():
    """
    Check if mail/sendmail command is available.
    
    Returns:
        Tuple of (available: bool, command: str or None)
    """
    for cmd in ['mail', 'sendmail']:
        result = subprocess.run(['which', cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return True, cmd
    return False, None


def send_email_alert(email_to, subject, body, sender=None):
    """
    Send alert via email using system mail command.
    
    Args:
        email_to: Recipient email address
        subject: Email subject
        body: Email body
        sender: Optional sender email
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    if not email_to:
        return False, "Email recipient is empty"
    
    if '\n' in email_to or '\r' in email_to:
        return False, "Email recipient contains invalid characters"
    if '@' not in email_to:
        return False, "Email recipient format invalid (missing @)"
    
    if sender:
        if '\n' in sender or '\r' in sender:
            return False, "Email sender contains invalid characters"
        if '@' not in sender:
            return False, "Email sender format invalid (missing @)"
    
    available, cmd = check_email_command()
    if not available:
        return False, "No mail command available (mail/sendmail)"
    
    try:
        if cmd == 'mail':
            mail_cmd = ['mail', '-s', subject]
            if sender:
                mail_cmd.extend(['-r', sender])
            mail_cmd.append(email_to)
            
            result = subprocess.run(
                mail_cmd,
                input=body.encode('utf-8'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30
            )
        else:
            mail_cmd = ['sendmail', '-t']
            email_content = f"Subject: {subject}\n"
            if sender:
                email_content += f"From: {sender}\n"
            email_content += f"To: {email_to}\n\n{body}"
            
            result = subprocess.run(
                mail_cmd,
                input=email_content.encode('utf-8'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30
            )
        
        if result.returncode == 0:
            return True, "Email sent successfully"
        else:
            return False, f"Mail command failed: {result.stderr.decode('utf-8', errors='ignore')}"
    except subprocess.TimeoutExpired:
        return False, "Email command timed out"
    except Exception as e:
        return False, f"Email error: {e}"


def format_ban_alert(ip, count, attack_types, config=None):
    """
    Format ban alert data.
    
    Args:
        ip: Banned IP address
        count: Attack count
        attack_types: Set of attack types
        config: Optional config dict with additional info
        
    Returns:
        Dictionary with alert data
    """
    data = {
        'event': 'ip_banned',
        'ip': ip,
        'attack_count': count,
        'attack_types': sorted(list(attack_types)) if isinstance(attack_types, set) else attack_types,
        'timestamp': datetime.now().isoformat(),
    }
    
    if config:
        if 'hostname' in config:
            data['hostname'] = config['hostname']
        if 'server_ip' in config:
            data['server_ip'] = config['server_ip']
    
    return data


def format_ban_alert_email(ip, count, attack_types, hostname=None, lang='zh'):
    """
    Format ban alert for email body.
    
    Args:
        ip: Banned IP address
        count: Attack count
        attack_types: Set of attack types
        hostname: Optional server hostname
        lang: Language code
        
    Returns:
        Email body string
    """
    types_str = ", ".join(sorted(attack_types)) if isinstance(attack_types, set) else str(attack_types)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if lang == 'zh':
        body = f"""安全告警 - IP 已被封禁

服务器: {hostname or 'N/A'}
时间: {timestamp}

封禁详情:
- IP 地址: {ip}
- 攻击次数: {count}
- 攻击类型: {types_str}

此 IP 已被自动添加到 iptables 封禁列表。

---
IP Ban Hammer 自动告警系统
"""
    else:
        body = f"""Security Alert - IP Banned

Server: {hostname or 'N/A'}
Time: {timestamp}

Ban Details:
- IP Address: {ip}
- Attack Count: {count}
- Attack Types: {types_str}

This IP has been automatically added to iptables ban list.

---
IP Ban Hammer Auto Alert System
"""
    
    return body


def send_alert(alert_config, ip, count, attack_types, hostname=None, lang='zh'):
    """
    Send alert via configured method.
    
    Args:
        alert_config: Dictionary with 'webhook_url' or 'email_to' keys
        ip: Banned IP address
        count: Attack count
        attack_types: Set of attack types
        hostname: Optional server hostname
        lang: Language code
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    webhook_url = alert_config.get('webhook_url')
    email_to = alert_config.get('email_to')
    sender = alert_config.get('email_sender')
    
    if webhook_url:
        data = format_ban_alert(ip, count, attack_types, {'hostname': hostname})
        success, msg = send_webhook_alert(webhook_url, data)
        if success:
            logger.info(f"Webhook alert sent for {ip}")
        else:
            logger.warning(f"Webhook alert failed for {ip}: {msg}")
        return success, msg
    
    if email_to:
        subject = f"[{hostname or 'Server'}] IP Ban Alert: {ip}" if lang == 'en' else f"[{hostname or '服务器'}] 安全告警: {ip} 已被封禁"
        body = format_ban_alert_email(ip, count, attack_types, hostname, lang)
        success, msg = send_email_alert(email_to, subject, body, sender)
        if success:
            logger.info(f"Email alert sent for {ip}")
        else:
            logger.warning(f"Email alert failed for {ip}: {msg}")
        return success, msg
    
    return False, "No alert method configured"
