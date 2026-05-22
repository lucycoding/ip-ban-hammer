"""
Tests for IP and CIDR validation utilities.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import unittest
from ipban_core.validators import (
    validate_ip,
    validate_ip_or_cidr,
    is_private_ip,
    should_skip_ip,
    is_in_whitelist
)


class TestValidateIP(unittest.TestCase):
    
    def test_valid_ip(self):
        self.assertTrue(validate_ip('192.168.1.1'))
        self.assertTrue(validate_ip('10.0.0.1'))
        self.assertTrue(validate_ip('127.0.0.1'))
        self.assertTrue(validate_ip('255.255.255.255'))
        self.assertTrue(validate_ip('0.0.0.0'))
    
    def test_invalid_ip_format(self):
        self.assertFalse(validate_ip('192.168.1'))
        self.assertFalse(validate_ip('192.168.1.1.1'))
        self.assertFalse(validate_ip(''))
        self.assertFalse(validate_ip(None))
        self.assertFalse(validate_ip('abc'))
        self.assertFalse(validate_ip('192.168.1.abc'))
    
    def test_invalid_ip_range(self):
        self.assertFalse(validate_ip('256.0.0.1'))
        self.assertFalse(validate_ip('192.168.1.256'))
        self.assertFalse(validate_ip('-1.0.0.1'))


class TestValidateIPorCIDR(unittest.TestCase):
    
    def test_valid_single_ip(self):
        self.assertTrue(validate_ip_or_cidr('192.168.1.1'))
        self.assertTrue(validate_ip_or_cidr('10.0.0.1'))
    
    def test_valid_cidr(self):
        self.assertTrue(validate_ip_or_cidr('10.0.0.0/8'))
        self.assertTrue(validate_ip_or_cidr('192.168.0.0/16'))
        self.assertTrue(validate_ip_or_cidr('172.16.0.0/12'))
        self.assertTrue(validate_ip_or_cidr('192.168.1.0/24'))
        self.assertTrue(validate_ip_or_cidr('192.168.1.1/32'))
    
    def test_invalid_cidr(self):
        self.assertFalse(validate_ip_or_cidr('192.168.1.0/33'))
        self.assertFalse(validate_ip_or_cidr('192.168.1.0/-1'))
        self.assertFalse(validate_ip_or_cidr(''))
        self.assertFalse(validate_ip_or_cidr(None))


class TestIsPrivateIP(unittest.TestCase):
    
    def test_private_class_a(self):
        self.assertTrue(is_private_ip('10.0.0.1'))
        self.assertTrue(is_private_ip('10.255.255.255'))
    
    def test_private_class_b(self):
        self.assertTrue(is_private_ip('172.16.0.1'))
        self.assertTrue(is_private_ip('172.31.255.255'))
    
    def test_private_class_c(self):
        self.assertTrue(is_private_ip('192.168.0.1'))
        self.assertTrue(is_private_ip('192.168.255.255'))
    
    def test_loopback(self):
        self.assertTrue(is_private_ip('127.0.0.1'))
        self.assertTrue(is_private_ip('127.255.255.255'))
    
    def test_link_local(self):
        self.assertTrue(is_private_ip('169.254.0.1'))
        self.assertTrue(is_private_ip('169.254.255.255'))
    
    def test_multicast(self):
        self.assertTrue(is_private_ip('224.0.0.1'))
        self.assertTrue(is_private_ip('239.255.255.255'))
    
    def test_public_ip(self):
        self.assertFalse(is_private_ip('8.8.8.8'))
        self.assertFalse(is_private_ip('1.1.1.1'))
        self.assertFalse(is_private_ip('203.0.113.50'))
    
    def test_invalid_ip(self):
        self.assertFalse(is_private_ip(''))
        self.assertFalse(is_private_ip(None))
        self.assertFalse(is_private_ip('invalid'))


class TestShouldSkipIP(unittest.TestCase):
    
    def test_skip_private_enabled(self):
        should_skip, reason = should_skip_ip('10.0.0.1', skip_private=True)
        self.assertTrue(should_skip)
        self.assertEqual(reason, 'private_ip')
    
    def test_skip_private_disabled(self):
        should_skip, reason = should_skip_ip('10.0.0.1', skip_private=False)
        self.assertFalse(should_skip)
        self.assertIsNone(reason)
    
    def test_public_ip_not_skipped(self):
        should_skip, reason = should_skip_ip('8.8.8.8', skip_private=True)
        self.assertFalse(should_skip)
        self.assertIsNone(reason)


class TestIsInWhitelist(unittest.TestCase):
    
    def test_exact_match(self):
        import ipaddress
        whitelist_single = {'192.168.1.1', '10.0.0.1'}
        whitelist_cidr = []
        
        self.assertTrue(is_in_whitelist('192.168.1.1', whitelist_single, whitelist_cidr))
        self.assertTrue(is_in_whitelist('10.0.0.1', whitelist_single, whitelist_cidr))
        self.assertFalse(is_in_whitelist('192.168.1.2', whitelist_single, whitelist_cidr))
    
    def test_cidr_match(self):
        import ipaddress
        whitelist_single = set()
        whitelist_cidr = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('192.168.0.0/16'),
        ]
        
        self.assertTrue(is_in_whitelist('10.0.0.1', whitelist_single, whitelist_cidr))
        self.assertTrue(is_in_whitelist('10.255.255.255', whitelist_single, whitelist_cidr))
        self.assertTrue(is_in_whitelist('192.168.1.100', whitelist_single, whitelist_cidr))
        self.assertFalse(is_in_whitelist('8.8.8.8', whitelist_single, whitelist_cidr))
    
    def test_combined_match(self):
        import ipaddress
        whitelist_single = {'1.2.3.4'}
        whitelist_cidr = [ipaddress.ip_network('10.0.0.0/8')]
        
        self.assertTrue(is_in_whitelist('1.2.3.4', whitelist_single, whitelist_cidr))
        self.assertTrue(is_in_whitelist('10.0.0.1', whitelist_single, whitelist_cidr))
        self.assertFalse(is_in_whitelist('8.8.8.8', whitelist_single, whitelist_cidr))


if __name__ == '__main__':
    unittest.main()
