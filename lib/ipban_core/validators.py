"""
IP and CIDR validation utilities for IP Ban Hammer.

Provides:
- IP address validation
- CIDR notation validation
- Private/reserved IP detection
- Whitelist matching
"""

import ipaddress

PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),       # Class A private
    ipaddress.ip_network('172.16.0.0/12'),    # Class B private
    ipaddress.ip_network('192.168.0.0/16'),   # Class C private
    ipaddress.ip_network('127.0.0.0/8'),      # Loopback
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local
    ipaddress.ip_network('224.0.0.0/4'),      # Multicast
    ipaddress.ip_network('240.0.0.0/4'),      # Reserved
    ipaddress.ip_network('0.0.0.0/8'),        # Current network
]


def validate_ip(ip_str):
    """
    Validate IPv4 address format and range.
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if valid, False otherwise
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except (ValueError, TypeError):
        return False


def is_ipv6(ip_str):
    """
    Check if string is a valid IPv6 address.
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if valid IPv6, False otherwise
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.version == 6
    except ValueError:
        return False


def validate_ip_or_cidr(ip_str):
    """
    Validate IP address or CIDR notation.
    
    Args:
        ip_str: IP address or CIDR string
        
    Returns:
        True if valid, False otherwise
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        if '/' in ip_str:
            ipaddress.ip_network(ip_str, strict=False)
        else:
            ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str):
    """
    Check if IP is private/reserved address.
    
    Includes:
    - 10.0.0.0/8 (Class A private)
    - 172.16.0.0/12 (Class B private)
    - 192.168.0.0/16 (Class C private)
    - 127.0.0.0/8 (Loopback)
    - 169.254.0.0/16 (Link-local)
    - 224.0.0.0/4 (Multicast)
    - 240.0.0.0/4 (Reserved)
    - 0.0.0.0/8 (Current network)
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if private/reserved, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def should_skip_ip(ip_str, skip_private=True):
    """
    Determine if an IP should be skipped from banning.
    
    Args:
        ip_str: IP address string
        skip_private: Whether to skip private IPs
        
    Returns:
        Tuple of (should_skip: bool, reason: str or None)
    """
    if skip_private and is_private_ip(ip_str):
        return True, "private_ip"
    return False, None


def is_in_whitelist(ip_str, whitelist_single, whitelist_cidr):
    """
    Check if IP is in whitelist (supports CIDR).
    
    Args:
        ip_str: IP address string
        whitelist_single: Set of single IP addresses
        whitelist_cidr: List of ipaddress network objects
        
    Returns:
        True if in whitelist, False otherwise
    """
    if ip_str in whitelist_single:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in network for network in whitelist_cidr)
    except ValueError:
        return False
