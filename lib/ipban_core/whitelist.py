"""
Whitelist handling utilities for IP Ban Hammer.

Provides:
- Whitelist loading from file
- Support for single IPs and CIDR notation
"""

import os
import ipaddress
import logging

logger = logging.getLogger(__name__)


def load_whitelist(whitelist_file):
    """
    Load whitelist from file (supports CIDR).
    
    Args:
        whitelist_file: Path to whitelist file
        
    Returns:
        Tuple of (whitelist_single: set, whitelist_cidr: list)
    """
    whitelist_single = set()
    whitelist_cidr = []
    
    if not os.path.exists(whitelist_file):
        return whitelist_single, whitelist_cidr
    
    try:
        with open(whitelist_file, 'r', encoding='utf-8') as f:
            for line in f:
                item = line.strip().split('#')[0].strip()
                if not item:
                    continue
                if '/' in item:
                    try:
                        whitelist_cidr.append(ipaddress.ip_network(item, strict=False))
                    except ValueError:
                        logger.warning(f"Invalid CIDR in whitelist, skipping: {item}")
                else:
                    try:
                        whitelist_single.add(str(ipaddress.ip_address(item)))
                    except ValueError:
                        logger.warning(f"Invalid IP in whitelist, skipping: {item}")
    except IOError as e:
        logger.error(f"Failed to read whitelist file {whitelist_file}: {e}")
    
    return whitelist_single, whitelist_cidr


def get_whitelist_count(whitelist_single, whitelist_cidr):
    """
    Get total count of whitelist entries.
    
    Args:
        whitelist_single: Set of single IPs
        whitelist_cidr: List of CIDR networks
        
    Returns:
        Total count
    """
    return len(whitelist_single) + len(whitelist_cidr)


def format_whitelist_display(whitelist_single, whitelist_cidr, max_items=10):
    """
    Format whitelist for display.
    
    Args:
        whitelist_single: Set of single IPs
        whitelist_cidr: List of CIDR networks
        max_items: Maximum items to display
        
    Returns:
        Formatted string
    """
    items = list(whitelist_single) + [str(net) for net in whitelist_cidr]
    display_items = sorted(items)[:max_items]
    display_str = ', '.join(display_items)
    if len(items) > max_items:
        display_str += f" ... (+{len(items) - max_items})"
    return display_str
