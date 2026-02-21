"""
Helper utility functions
"""
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Dict
from uuid import UUID

def hash_data(data: Any) -> str:
    """
    Create SHA256 hash of data for integrity verification
    """
    if isinstance(data, dict):
        data_str = json.dumps(data, sort_keys=True)
    else:
        data_str = str(data)
    
    return hashlib.sha256(data_str.encode()).hexdigest()


def calculate_rollback_deadline(duration_minutes: int) -> datetime:
    """
    Calculate when an action should auto-expire
    """
    return datetime.utcnow() + timedelta(minutes=duration_minutes)


def sanitize_ip(ip: str) -> str:
    """
    Sanitize IP address for safe storage
    """
    return ip.strip().lower()


def extract_iocs(alert_data: Dict[str, Any]) -> Dict[str, list]:
    """
    Extract Indicators of Compromise from alert data
    Returns: {
        'ips': [...],
        'domains': [...],
        'hashes': [...],
        'urls': [...]
    }
    """
    iocs = {
        'ips': [],
        'domains': [],
        'hashes': [],
        'urls': []
    }
    
    # Recursive function to search nested dicts
    def search_dict(d: dict):
        for key, value in d.items():
            key_lower = key.lower()
            
            # Look for IPs
            if 'ip' in key_lower or 'address' in key_lower:
                if isinstance(value, str):
                    iocs['ips'].append(value)
            
            # Look for domains
            elif 'domain' in key_lower or 'hostname' in key_lower:
                if isinstance(value, str):
                    iocs['domains'].append(value)
            
            # Look for hashes
            elif 'hash' in key_lower or 'md5' in key_lower or 'sha' in key_lower:
                if isinstance(value, str):
                    iocs['hashes'].append(value)
            
            # Look for URLs
            elif 'url' in key_lower:
                if isinstance(value, str):
                    iocs['urls'].append(value)
            
            # Recurse into nested dicts
            elif isinstance(value, dict):
                search_dict(value)
            
            # Search arrays
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        search_dict(item)
    
    search_dict(alert_data)
    
    # Remove duplicates
    for key in iocs:
        iocs[key] = list(set(iocs[key]))
    
    return iocs


def is_private_ip(ip: str) -> bool:
    """
    Check if IP is in private/internal range
    """
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False


def normalize_alert(source_system: str, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize alerts from different sources into common format
    
    Common format:
    {
        'timestamp': '2024-01-07T10:30:00Z',
        'severity': 'high',
        'title': 'Short description',
        'description': 'Detailed description',
        'source_host': 'hostname',
        'source_ip': 'x.x.x.x',
        'user': 'username',
        'process': 'process_name',
        'command_line': 'full command',
        'file_hash': 'sha256...',
        'iocs': {...}
    }
    """
    normalized = {
        'timestamp': datetime.utcnow().isoformat(),
        'severity': 'medium',
        'title': 'Security Alert',
        'description': '',
        'source_host': None,
        'source_ip': None,
        'user': None,
        'process': None,
        'command_line': None,
        'file_hash': None,
        'iocs': extract_iocs(raw_alert)
    }
    
    # Source-specific normalization
    if source_system.lower() == 'wazuh':
        normalized.update({
            'timestamp': raw_alert.get('timestamp', normalized['timestamp']),
            'title': raw_alert.get('rule', {}).get('description', 'Wazuh Alert'),
            'description': raw_alert.get('full_log', ''),
            'severity': _map_wazuh_severity(raw_alert.get('rule', {}).get('level', 5)),
            'source_host': raw_alert.get('agent', {}).get('name'),
            'source_ip': raw_alert.get('agent', {}).get('ip'),
        })
    
    elif source_system.lower() == 'splunk':
        normalized.update({
            'timestamp': raw_alert.get('_time', normalized['timestamp']),
            'title': raw_alert.get('search_name', 'Splunk Alert'),
            'description': raw_alert.get('message', ''),
            'severity': raw_alert.get('severity', 'medium'),
            'source_host': raw_alert.get('host'),
            'source_ip': raw_alert.get('src_ip'),
        })
    
    elif source_system.lower() == 'elastic':
        normalized.update({
            'timestamp': raw_alert.get('@timestamp', normalized['timestamp']),
            'title': raw_alert.get('rule', {}).get('name', 'Elastic Alert'),
            'description': raw_alert.get('message', ''),
            'severity': raw_alert.get('severity', 'medium'),
            'source_host': raw_alert.get('host', {}).get('name'),
            'source_ip': raw_alert.get('source', {}).get('ip'),
        })
    
    return normalized


def _map_wazuh_severity(level: int) -> str:
    """Map Wazuh alert level to severity"""
    if level >= 12:
        return 'critical'
    elif level >= 7:
        return 'high'
    elif level >= 4:
        return 'medium'
    else:
        return 'low'