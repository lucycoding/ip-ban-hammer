"""
Configuration migration utilities for IP Ban Hammer.

Handles:
- Detecting old config versions
- Backing up old configs
"""

import os
import shutil
import configparser
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

CURRENT_VERSION = '1.0.0'


def get_config_version(config_file):
    """
    Get version from config file.
    
    Args:
        config_file: Path to config file
        
    Returns:
        Version string or '1.0.0' if not found
    """
    config = configparser.ConfigParser()
    try:
        config.read(config_file, encoding='utf-8')
        if config.has_option('general', 'config_version'):
            return config.get('general', 'config_version')
    except Exception:
        pass
    return '1.0.0'


def needs_migration(config_file):
    """
    Check if config needs migration.
    
    Args:
        config_file: Path to config file
        
    Returns:
        Tuple of (needs_migration: bool, old_version: str)
    """
    if not os.path.exists(config_file):
        return False, None
    
    version = get_config_version(config_file)
    return version != CURRENT_VERSION, version


def backup_config(config_file, backup_dir=None):
    """
    Backup config file before migration.
    
    Args:
        config_file: Path to config file
        backup_dir: Optional backup directory
        
    Returns:
        Path to backup file or None on failure
    """
    if not os.path.exists(config_file):
        return None
    
    if backup_dir is None:
        backup_dir = os.path.dirname(config_file)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = f"{os.path.basename(config_file)}.backup_{timestamp}"
    backup_path = os.path.join(backup_dir, backup_name)
    
    try:
        shutil.copy2(config_file, backup_path)
        logger.info(f"Config backed up to: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to backup config: {e}")
        return None


def migrate_config(config_file, dry_run=False):
    """
    Perform config migration if needed.
    
    Args:
        config_file: Path to config file
        dry_run: If True, don't actually modify files
        
    Returns:
        Tuple of (success: bool, message: str, backup_path: str or None)
    """
    needs_mig, old_version = needs_migration(config_file)
    
    if not needs_mig:
        return True, f"Config is already v{CURRENT_VERSION}", None
    
    logger.info(f"Config needs migration: {old_version} -> {CURRENT_VERSION}")
    
    return False, f"Unknown version: {old_version}", None


def check_and_migrate_config(config_file, auto_migrate=True):
    """
    Check and optionally migrate config file.
    
    Args:
        config_file: Path to config file
        auto_migrate: If True, automatically migrate; if False, just check
        
    Returns:
        Tuple of (needs_migration: bool, current_version: str, message: str)
    """
    needs_mig, old_version = needs_migration(config_file)
    
    if not needs_mig:
        return False, CURRENT_VERSION, "Config is up to date"
    
    return True, old_version, f"Config needs migration: {old_version} -> {CURRENT_VERSION}"
