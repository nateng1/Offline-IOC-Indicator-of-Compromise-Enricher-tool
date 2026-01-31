"""
Exporters - Export enriched IOCs to various formats
"""

import json
import csv
from io import StringIO
from typing import List, Dict


class BaseExporter:
    """Base class for exporters"""
    
    def export(self, iocs: List[Dict]) -> str:
        """Export IOCs to string format"""
        raise NotImplementedError


class JSONExporter(BaseExporter):
    """Export IOCs to JSON format"""
    
    def export(self, iocs: List[Dict]) -> str:
        """
        Export IOCs to JSON format
        
        Args:
            iocs: List of enriched IOC dictionaries
            
        Returns:
            JSON string
        """
        return json.dumps(iocs, indent=2, ensure_ascii=False)


class CSVExporter(BaseExporter):
    """Export IOCs to CSV format for SIEM ingestion"""
    
    def export(self, iocs: List[Dict]) -> str:
        """
        Export IOCs to CSV format
        
        Args:
            iocs: List of enriched IOC dictionaries
            
        Returns:
            CSV string
        """
        if not iocs:
            return "ioc,type,tags,normalized\n"
        
        output = StringIO()
        fieldnames = ['ioc', 'type', 'tags', 'normalized']
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for ioc in iocs:
            # Convert tags list to comma-separated string
            row = {
                'ioc': ioc['ioc'],
                'type': ioc['type'],
                'tags': ','.join(ioc['tags']) if ioc['tags'] else '',
                'normalized': ioc['normalized']
            }
            writer.writerow(row)
        
        return output.getvalue()


class SIEMExporter(BaseExporter):
    """Export IOCs in SIEM-friendly JSON format"""
    
    def export(self, iocs: List[Dict]) -> str:
        """
        Export IOCs in SIEM-compatible format
        
        Args:
            iocs: List of enriched IOC dictionaries
            
        Returns:
            SIEM-formatted JSON string
        """
        siem_format = []
        
        for ioc in iocs:
            event = {
                'event_type': 'ioc_indicator',
                'indicator': ioc['ioc'],
                'indicator_type': ioc['type'],
                'threat_tags': ioc['tags'],
                'normalized_value': ioc['normalized'],
                'confidence': self._calculate_confidence(ioc)
            }
            siem_format.append(event)
        
        return json.dumps(siem_format, indent=2)
    
    def _calculate_confidence(self, ioc: Dict) -> str:
        """
        Calculate confidence level based on tags
        
        Args:
            ioc: IOC dictionary with tags
            
        Returns:
            Confidence level: 'high', 'medium', or 'low'
        """
        tags = ioc.get('tags', [])
        
        # High confidence indicators
        high_confidence_tags = [
            'suspicious_pattern', 'suspicious_tld', 'potential_dga',
            'suspicious_path', 'ip_based_url'
        ]
        
        # Low confidence indicators
        low_confidence_tags = ['private_ip', 'known_tld', 'free_email_provider']
        
        high_count = sum(1 for tag in tags if tag in high_confidence_tags)
        low_count = sum(1 for tag in tags if tag in low_confidence_tags)
        
        if high_count >= 2:
            return 'high'
        elif high_count >= 1:
            return 'medium'
        elif low_count >= 2:
            return 'low'
        else:
            return 'medium'


class STIXExporter(BaseExporter):
    """Export IOCs in STIX 2.1 format (simplified)"""
    
    def export(self, iocs: List[Dict]) -> str:
        """
        Export IOCs in simplified STIX 2.1 format
        
        Args:
            iocs: List of enriched IOC dictionaries
            
        Returns:
            STIX JSON string
        """
        import datetime
        
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{self._generate_uuid()}",
            "objects": []
        }
        
        for ioc in iocs:
            # Map IOC type to STIX pattern type
            stix_type = self._map_to_stix_type(ioc['type'])
            
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{self._generate_uuid()}",
                "created": datetime.datetime.utcnow().isoformat() + "Z",
                "modified": datetime.datetime.utcnow().isoformat() + "Z",
                "name": f"{ioc['type'].upper()} Indicator",
                "pattern": self._create_stix_pattern(ioc['normalized'], stix_type),
                "pattern_type": "stix",
                "valid_from": datetime.datetime.utcnow().isoformat() + "Z",
                "labels": ioc['tags']
            }
            
            stix_bundle["objects"].append(indicator)
        
        return json.dumps(stix_bundle, indent=2)
    
    def _map_to_stix_type(self, ioc_type: str) -> str:
        """Map IOC type to STIX cyber observable type"""
        mapping = {
            'ipv4': 'ipv4-addr',
            'ipv6': 'ipv6-addr',
            'domain': 'domain-name',
            'url': 'url',
            'md5': 'file',
            'sha1': 'file',
            'sha256': 'file',
            'email': 'email-addr'
        }
        return mapping.get(ioc_type, 'unknown')
    
    def _create_stix_pattern(self, value: str, stix_type: str) -> str:
        """Create STIX pattern string"""
        if stix_type == 'ipv4-addr':
            return f"[ipv4-addr:value = '{value}']"
        elif stix_type == 'ipv6-addr':
            return f"[ipv6-addr:value = '{value}']"
        elif stix_type == 'domain-name':
            return f"[domain-name:value = '{value}']"
        elif stix_type == 'url':
            return f"[url:value = '{value}']"
        elif stix_type == 'file':
            return f"[file:hashes.MD5 = '{value}' OR file:hashes.SHA1 = '{value}' OR file:hashes.'SHA-256' = '{value}']"
        elif stix_type == 'email-addr':
            return f"[email-addr:value = '{value}']"
        else:
            return f"[unknown:value = '{value}']"
    
    def _generate_uuid(self) -> str:
        """Generate a simple UUID for STIX objects"""
        import uuid
        return str(uuid.uuid4())
