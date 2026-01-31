"""
IOC Validator - Validate and normalize IOCs
"""

import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse


class IOCValidator:
    """Validate and normalize various IOC types"""
    
    def __init__(self):
        # Common suspicious TLDs
        self.suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click',
            'link', 'zip', 'review', 'country', 'stream', 'download',
            'racing', 'loan', 'win', 'bid', 'date', 'faith', 'science'
        }
        
        # Known legitimate TLDs (subset)
        self.known_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
            'co', 'uk', 'de', 'jp', 'fr', 'au', 'us', 'ca', 'cn', 'in'
        }
    
    def is_valid(self, ioc: str, ioc_type: str) -> bool:
        """
        Validate an IOC based on its type
        
        Args:
            ioc: The IOC value to validate
            ioc_type: The type of IOC
            
        Returns:
            True if valid, False otherwise
        """
        validators = {
            'ipv4': self._validate_ipv4,
            'ipv6': self._validate_ipv6,
            'domain': self._validate_domain,
            'url': self._validate_url,
            'md5': self._validate_md5,
            'sha1': self._validate_sha1,
            'sha256': self._validate_sha256,
            'email': self._validate_email,
        }
        
        validator = validators.get(ioc_type)
        if validator is None:
            return False
        
        return validator(ioc)
    
    def normalize(self, ioc: str, ioc_type: str) -> str:
        """
        Normalize an IOC to a standard format
        
        Args:
            ioc: The IOC value to normalize
            ioc_type: The type of IOC
            
        Returns:
            Normalized IOC string
        """
        normalizers = {
            'ipv4': self._normalize_ip,
            'ipv6': self._normalize_ip,
            'domain': self._normalize_domain,
            'url': self._normalize_url,
            'md5': lambda x: x.lower(),
            'sha1': lambda x: x.lower(),
            'sha256': lambda x: x.lower(),
            'email': lambda x: x.lower(),
        }
        
        normalizer = normalizers.get(ioc_type, lambda x: x)
        return normalizer(ioc)
    
    def _validate_ipv4(self, ip: str) -> bool:
        """Validate IPv4 address"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    def _validate_ipv6(self, ip: str) -> bool:
        """Validate IPv6 address"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name"""
        if len(domain) > 253:
            return False
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return False
        
        # Check each label
        labels = domain.split('.')
        if len(labels) < 2:
            return False
        
        for label in labels:
            if not label or len(label) > 63:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
        
        return True
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def _validate_md5(self, hash_str: str) -> bool:
        """Validate MD5 hash"""
        return bool(re.match(r'^[a-fA-F0-9]{32}$', hash_str))
    
    def _validate_sha1(self, hash_str: str) -> bool:
        """Validate SHA1 hash"""
        return bool(re.match(r'^[a-fA-F0-9]{40}$', hash_str))
    
    def _validate_sha256(self, hash_str: str) -> bool:
        """Validate SHA256 hash"""
        return bool(re.match(r'^[a-fA-F0-9]{64}$', hash_str))
    
    def _validate_email(self, email: str) -> bool:
        """Validate email address"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address"""
        try:
            # This handles both IPv4 and IPv6
            return str(ipaddress.ip_address(ip))
        except Exception:
            return ip
    
    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain name"""
        # Convert to lowercase and remove trailing dot
        return domain.lower().rstrip('.')
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        # Refang if defanged
        url = url.replace('hxxp', 'http')
        url = url.replace('hxxps', 'https')
        url = url.replace('[.]', '.')
        url = url.replace('[:', ':')
        url = url.replace(':]', ':')
        
        return url.lower()
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except Exception:
            return False
    
    def get_tld(self, domain: str) -> Optional[str]:
        """Extract TLD from domain"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return parts[-1].lower()
        return None
