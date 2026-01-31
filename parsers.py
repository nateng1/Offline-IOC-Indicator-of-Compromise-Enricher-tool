"""
IOC Parser - Extract IOCs from text using regex patterns
"""

import re
from typing import List, Dict


class IOCParser:
    """Extract various types of IOCs from raw text"""
    
    def __init__(self):
        # Regex patterns for different IOC types
        self.patterns = {
            'ipv4': re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ),
            'ipv6': re.compile(
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
                r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
                r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
            ),
            'domain': re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            ),
            'url': re.compile(
                r'(?:https?|ftp|hxxps?|fxp)://[^\s/$.?#].[^\s]*',
                re.IGNORECASE
            ),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'email': re.compile(
                r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            ),
        }
    
    def extract_all(self, text: str) -> List[Dict]:
        """
        Extract all IOC types from text
        
        Args:
            text: Raw text to parse
            
        Returns:
            List of dictionaries with 'value' and 'type' keys
        """
        iocs = []
        
        for ioc_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                iocs.append({
                    'value': match,
                    'type': ioc_type
                })
        
        return iocs
    
    def extract_type(self, text: str, ioc_type: str) -> List[str]:
        """
        Extract specific IOC type from text
        
        Args:
            text: Raw text to parse
            ioc_type: Type of IOC to extract (e.g., 'ipv4', 'domain')
            
        Returns:
            List of extracted IOC values
        """
        if ioc_type not in self.patterns:
            raise ValueError(f"Unknown IOC type: {ioc_type}")
        
        pattern = self.patterns[ioc_type]
        return pattern.findall(text)
    
    def extract_ips(self, text: str) -> List[str]:
        """Extract all IP addresses (v4 and v6)"""
        ipv4 = self.extract_type(text, 'ipv4')
        ipv6 = self.extract_type(text, 'ipv6')
        return ipv4 + ipv6
    
    def extract_domains(self, text: str) -> List[str]:
        """Extract all domain names"""
        return self.extract_type(text, 'domain')
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs"""
        return self.extract_type(text, 'url')
    
    def extract_hashes(self, text: str) -> List[Dict]:
        """Extract all file hashes with their types"""
        hashes = []
        for hash_type in ['md5', 'sha1', 'sha256']:
            matches = self.extract_type(text, hash_type)
            for match in matches:
                hashes.append({
                    'value': match,
                    'type': hash_type
                })
        return hashes
