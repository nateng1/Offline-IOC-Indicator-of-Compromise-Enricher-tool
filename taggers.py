"""
IOC Tagger - Apply threat intelligence tags to IOCs
"""

import ipaddress
from typing import List, Set
from validators import IOCValidator


class IOCTagger:
    """Apply contextual tags to IOCs based on characteristics"""
    
    def __init__(self):
        self.validator = IOCValidator()
        
        # Suspicious keywords for pattern matching
        self.suspicious_keywords = {
            'malware', 'evil', 'phish', 'hack', 'exploit', 'payload',
            'ransomware', 'trojan', 'backdoor', 'botnet', 'c2', 'c&c',
            'virus', 'worm', 'rat', 'suspicious', 'malicious', 'bad'
        }
        
        # Suspicious TLDs (already defined in validator)
        self.suspicious_tlds = self.validator.suspicious_tlds
        self.known_tlds = self.validator.known_tlds
    
    def tag(self, ioc: str, ioc_type: str) -> List[str]:
        """
        Apply all relevant tags to an IOC
        
        Args:
            ioc: The IOC value
            ioc_type: The type of IOC
            
        Returns:
            List of tags
        """
        tags = set()
        
        # Apply type-specific tags
        if ioc_type in ['ipv4', 'ipv6']:
            tags.update(self._tag_ip(ioc, ioc_type))
        elif ioc_type == 'domain':
            tags.update(self._tag_domain(ioc))
        elif ioc_type == 'url':
            tags.update(self._tag_url(ioc))
        elif ioc_type in ['md5', 'sha1', 'sha256']:
            tags.update(self._tag_hash(ioc, ioc_type))
        elif ioc_type == 'email':
            tags.update(self._tag_email(ioc))
        
        # Apply pattern-based tags (common to all types)
        tags.update(self._tag_patterns(ioc))
        
        return sorted(list(tags))
    
    def _tag_ip(self, ip: str, ioc_type: str) -> Set[str]:
        """Tag IP addresses"""
        tags = set()
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if private
            if ip_obj.is_private:
                tags.add('private_ip')
                tags.add('rfc1918')
            else:
                tags.add('public_ip')
            
            # Check if loopback
            if ip_obj.is_loopback:
                tags.add('loopback')
            
            # Check if multicast
            if ip_obj.is_multicast:
                tags.add('multicast')
            
            # Check if reserved
            if ip_obj.is_reserved:
                tags.add('reserved')
            
            # Check if link-local
            if ip_obj.is_link_local:
                tags.add('link_local')
            
        except Exception:
            tags.add('invalid_ip')
        
        return tags
    
    def _tag_domain(self, domain: str) -> Set[str]:
        """Tag domain names"""
        tags = set()
        
        # Get TLD
        tld = self.validator.get_tld(domain)
        
        if tld:
            if tld in self.suspicious_tlds:
                tags.add('suspicious_tld')
            elif tld in self.known_tlds:
                tags.add('known_tld')
            else:
                tags.add('uncommon_tld')
        
        # Check domain length
        if len(domain) > 50:
            tags.add('long_domain')
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            tags.add('many_subdomains')
        
        # Check for numbers in domain
        if any(char.isdigit() for char in domain):
            tags.add('contains_numbers')
        
        # Check for hyphens (can be suspicious)
        if '-' in domain:
            tags.add('contains_hyphen')
        
        # Check for potential DGA patterns (high entropy, random-looking)
        if self._is_dga_like(domain):
            tags.add('potential_dga')
        
        return tags
    
    def _tag_url(self, url: str) -> Set[str]:
        """Tag URLs"""
        tags = set()
        
        # Check for defanged URLs
        if 'hxxp' in url.lower() or '[.]' in url or '[:]' in url:
            tags.add('url_defanged')
        
        # Check for suspicious paths
        suspicious_paths = [
            '/admin', '/wp-admin', '/login', '/portal', '/upload',
            '/shell', '/cmd', '/exec', '.php', '.asp', '.jsp'
        ]
        
        url_lower = url.lower()
        for path in suspicious_paths:
            if path in url_lower:
                tags.add('suspicious_path')
                break
        
        # Check for IP-based URLs
        import re
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
            tags.add('ip_based_url')
        
        return tags
    
    def _tag_hash(self, hash_str: str, hash_type: str) -> Set[str]:
        """Tag file hashes"""
        tags = set()
        
        # Add hash type tag
        tags.add(f'hash_{hash_type}')
        
        # Check for known weak hash
        if hash_type == 'md5':
            tags.add('weak_hash')
        
        return tags
    
    def _tag_email(self, email: str) -> Set[str]:
        """Tag email addresses"""
        tags = set()
        
        # Extract domain from email
        if '@' in email:
            domain = email.split('@')[1]
            
            # Check if using suspicious TLD
            tld = self.validator.get_tld(domain)
            if tld in self.suspicious_tlds:
                tags.add('suspicious_email_domain')
            
            # Check for common free email providers
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 
                            'outlook.com', 'aol.com', 'protonmail.com']
            if domain.lower() in free_providers:
                tags.add('free_email_provider')
        
        return tags
    
    def _tag_patterns(self, ioc: str) -> Set[str]:
        """Tag based on suspicious patterns in the IOC string"""
        tags = set()
        
        ioc_lower = ioc.lower()
        
        # Check for suspicious keywords
        for keyword in self.suspicious_keywords:
            if keyword in ioc_lower:
                tags.add('suspicious_pattern')
                tags.add(f'keyword_{keyword}')
                break
        
        return tags
    
    def _is_dga_like(self, domain: str) -> bool:
        """
        Simple heuristic to detect DGA-like domains
        (Domain Generation Algorithm - random-looking domains)
        """
        # Remove TLD for analysis
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return False
        
        main_part = domain_parts[-2]  # The part before TLD
        
        # Check for high consonant ratio
        consonants = 'bcdfghjklmnpqrstvwxyz'
        vowels = 'aeiou'
        
        if len(main_part) < 6:
            return False
        
        consonant_count = sum(1 for c in main_part.lower() if c in consonants)
        vowel_count = sum(1 for c in main_part.lower() if c in vowels)
        
        # DGA domains often have unusual consonant/vowel ratios
        if vowel_count == 0:
            return True
        
        ratio = consonant_count / vowel_count
        if ratio > 3.5:
            return True
        
        # Check for lack of dictionary words (simplified)
        # In a real implementation, you'd use a dictionary
        return False
