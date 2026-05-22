"""
Configuration loading utilities for IP Ban Hammer.

Provides:
- INI config file parsing
- Type-safe config value retrieval
- Default value fallbacks
"""

import os
import configparser
import logging

logger = logging.getLogger(__name__)

RUNTIME_CONFIG = "/etc/ip-ban-hammer/security.conf"


def get_config_path(script_dir):
    """
    Determine config file path.
    
    Args:
        script_dir: Directory of the calling script
        
    Returns:
        Path to config file
    """
    root_dir = os.path.dirname(script_dir)
    default_config = os.path.join(root_dir, "config", "security.conf")
    return RUNTIME_CONFIG if os.path.exists(RUNTIME_CONFIG) else default_config


def load_config(config_file):
    """
    Load configuration from INI file.
    
    Args:
        config_file: Path to config file
        
    Returns:
        ConfigParser object
    """
    config = configparser.ConfigParser()
    if os.path.exists(config_file):
        try:
            config.read(config_file, encoding='utf-8')
        except configparser.Error as e:
            logger.error(f"Failed to read config file {config_file}: {e}")
    return config


def get_path(config, key, default):
    """
    Get path value from config.
    
    Args:
        config: ConfigParser object
        key: Config key
        default: Default value
        
    Returns:
        Path string
    """
    return config.get('paths', key, fallback=default) if config.has_section('paths') else default


def get_int(config, section, key, default):
    """
    Get integer value from config with fallback.
    
    Args:
        config: ConfigParser object
        section: Config section
        key: Config key
        default: Default value
        
    Returns:
        Integer value
    """
    try:
        return config.getint(section, key, fallback=default)
    except (ValueError, configparser.Error) as e:
        logger.warning(f"Invalid config value for {section}.{key}, using default {default}: {e}")
        return default


def get_str(config, section, key, default=''):
    """
    Get string value from config with fallback.
    
    Args:
        config: ConfigParser object
        section: Config section
        key: Config key
        default: Default value
        
    Returns:
        String value
    """
    try:
        return config.get(section, key, fallback=default)
    except configparser.Error:
        return default


def get_bool(config, section, key, default=False):
    """
    Get boolean value from config with fallback.
    
    Args:
        config: ConfigParser object
        section: Config section
        key: Config key
        default: Default value
        
    Returns:
        Boolean value
    """
    try:
        return config.getboolean(section, key, fallback=default)
    except (ValueError, configparser.Error) as e:
        logger.warning(f"Invalid config value for {section}.{key}, using default {default}: {e}")
        return default


def get_language(config):
    """
    Get language setting from config.
    
    Args:
        config: ConfigParser object
        
    Returns:
        Language code string (default: 'zh')
    """
    return config.get('general', 'language', fallback='zh') if config.has_section('general') else 'zh'
