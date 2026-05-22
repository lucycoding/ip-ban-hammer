"""
Backup and rollback utilities for IP Ban Hammer.

Provides:
- Backup of iptables rules
- Backup of data files
- Rollback to previous state
"""

import os
import shutil
import subprocess
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def get_backup_dir(base_dir='/var/lib/ip-ban-hammer'):
    """
    Get backup directory path.
    
    Args:
        base_dir: Base data directory
        
    Returns:
        Backup directory path
    """
    return os.path.join(base_dir, 'backups')


def create_backup(backup_name=None, base_dir='/var/lib/ip-ban-hammer', 
                  config_dir='/etc/ip-ban-hammer', log_dir='/var/log/ip-ban-hammer'):
    """
    Create a full backup of IP Ban Hammer state.
    
    Args:
        backup_name: Optional backup name (default: timestamp)
        base_dir: Base data directory
        config_dir: Config directory
        log_dir: Log directory
        
    Returns:
        Tuple of (success: bool, backup_path: str or None, message: str)
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = backup_name or f"backup_{timestamp}"
    
    backup_dir = get_backup_dir(base_dir)
    backup_path = os.path.join(backup_dir, backup_name)
    
    try:
        os.makedirs(backup_path, exist_ok=True)
    except Exception as e:
        return False, None, f"Failed to create backup directory: {e}"
    
    backed_up = []
    
    data_files = ['pending.list', 'applied.list']
    for fname in data_files:
        src = os.path.join(base_dir, fname)
        if os.path.exists(src):
            dst = os.path.join(backup_path, fname)
            try:
                shutil.copy2(src, dst)
                backed_up.append(fname)
            except Exception as e:
                logger.warning(f"Failed to backup {fname}: {e}")
    
    config_file = os.path.join(config_dir, 'security.conf')
    if os.path.exists(config_file):
        dst = os.path.join(backup_path, 'security.conf')
        try:
            shutil.copy2(config_file, dst)
            backed_up.append('security.conf')
        except Exception as e:
            logger.warning(f"Failed to backup security.conf: {e}")
    
    allow_file = os.path.join(config_dir, 'allow.list')
    if os.path.exists(allow_file):
        dst = os.path.join(backup_path, 'allow.list')
        try:
            shutil.copy2(allow_file, dst)
            backed_up.append('allow.list')
        except Exception as e:
            logger.warning(f"Failed to backup allow.list: {e}")
    
    iptables_backup = os.path.join(backup_path, 'iptables.rules')
    try:
        result = subprocess.run(
            ['iptables-save'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=30
        )
        if result.returncode == 0:
            with open(iptables_backup, 'w') as f:
                f.write(result.stdout)
            backed_up.append('iptables.rules')
    except Exception as e:
        logger.warning(f"Failed to backup iptables rules: {e}")
    
    metadata = {
        'timestamp': timestamp,
        'files': backed_up,
    }
    metadata_file = os.path.join(backup_path, 'metadata.txt')
    try:
        with open(metadata_file, 'w') as f:
            f.write(f"timestamp={timestamp}\n")
            f.write(f"files={','.join(backed_up)}\n")
    except Exception as e:
        logger.warning(f"Failed to write metadata: {e}")
    
    return True, backup_path, f"Backup created: {len(backed_up)} files"


def list_backups(base_dir='/var/lib/ip-ban-hammer'):
    """
    List available backups.
    
    Args:
        base_dir: Base data directory
        
    Returns:
        List of backup info dicts
    """
    backup_dir = get_backup_dir(base_dir)
    
    if not os.path.exists(backup_dir):
        return []
    
    backups = []
    for name in os.listdir(backup_dir):
        path = os.path.join(backup_dir, name)
        if os.path.isdir(path):
            metadata_file = os.path.join(path, 'metadata.txt')
            info = {'name': name, 'path': path}
            
            if os.path.exists(metadata_file):
                try:
                    with open(metadata_file, 'r') as f:
                        for line in f:
                            if '=' in line:
                                key, value = line.strip().split('=', 1)
                                info[key] = value
                except Exception:
                    pass
            
            info['date'] = datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
            backups.append(info)
    
    backups.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return backups


def rollback(backup_name, base_dir='/var/lib/ip-ban-hammer', 
             config_dir='/etc/ip-ban-hammer', restore_iptables=True):
    """
    Rollback to a previous backup.
    
    Args:
        backup_name: Name of backup to restore
        base_dir: Base data directory
        config_dir: Config directory
        restore_iptables: Whether to restore iptables rules
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    backup_dir = get_backup_dir(base_dir)
    backup_path = os.path.join(backup_dir, backup_name)
    
    if not os.path.exists(backup_path):
        return False, f"Backup not found: {backup_name}"
    
    restored = []
    
    for fname in ['pending.list', 'applied.list']:
        src = os.path.join(backup_path, fname)
        if os.path.exists(src):
            dst = os.path.join(base_dir, fname)
            try:
                shutil.copy2(src, dst)
                restored.append(fname)
            except Exception as e:
                logger.warning(f"Failed to restore {fname}: {e}")
    
    config_src = os.path.join(backup_path, 'security.conf')
    if os.path.exists(config_src):
        config_dst = os.path.join(config_dir, 'security.conf')
        try:
            shutil.copy2(config_src, config_dst)
            restored.append('security.conf')
        except Exception as e:
            logger.warning(f"Failed to restore security.conf: {e}")
    
    allow_src = os.path.join(backup_path, 'allow.list')
    if os.path.exists(allow_src):
        allow_dst = os.path.join(config_dir, 'allow.list')
        try:
            shutil.copy2(allow_src, allow_dst)
            restored.append('allow.list')
        except Exception as e:
            logger.warning(f"Failed to restore allow.list: {e}")
    
    if restore_iptables:
        iptables_src = os.path.join(backup_path, 'iptables.rules')
        if os.path.exists(iptables_src):
            try:
                with open(iptables_src, 'r') as f:
                    rules = f.read()
                result = subprocess.run(
                    ['iptables-restore'],
                    input=rules.encode(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30
                )
                if result.returncode == 0:
                    restored.append('iptables.rules')
                else:
                    logger.warning(f"iptables-restore failed: {result.stderr.decode()}")
            except Exception as e:
                logger.warning(f"Failed to restore iptables: {e}")
    
    return True, f"Restored {len(restored)} items: {', '.join(restored)}"


def delete_backup(backup_name, base_dir='/var/lib/ip-ban-hammer'):
    """
    Delete a backup.
    
    Args:
        backup_name: Name of backup to delete
        base_dir: Base data directory
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    backup_dir = get_backup_dir(base_dir)
    backup_path = os.path.join(backup_dir, backup_name)
    
    if not os.path.exists(backup_path):
        return False, f"Backup not found: {backup_name}"
    
    try:
        shutil.rmtree(backup_path)
        return True, f"Backup deleted: {backup_name}"
    except Exception as e:
        return False, f"Failed to delete backup: {e}"


def cleanup_old_backups(max_backups=10, base_dir='/var/lib/ip-ban-hammer'):
    """
    Remove old backups, keeping only the most recent ones.
    
    Args:
        max_backups: Maximum number of backups to keep
        base_dir: Base data directory
        
    Returns:
        Tuple of (deleted_count: int, message: str)
    """
    backups = list_backups(base_dir)
    
    if len(backups) <= max_backups:
        return 0, f"Only {len(backups)} backups, no cleanup needed"
    
    to_delete = backups[max_backups:]
    deleted = 0
    
    for backup in to_delete:
        success, _ = delete_backup(backup['name'], base_dir)
        if success:
            deleted += 1
    
    return deleted, f"Deleted {deleted} old backups, keeping {max_backups}"
