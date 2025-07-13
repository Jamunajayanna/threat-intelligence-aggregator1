import re
import logging

logger = logging.getLogger(__name__)

def extract_iocs(text):
    """
    Extract Indicators of Compromise (IOCs) from text
    Returns a dictionary with different types of IOCs
    """
    if not text:
        return {
            'urls': [],
            'ips': [],
            'domains': [],
            'hashes': [],
            'emails': []
        }
    
    text = str(text).lower()
    
    # URL patterns
    url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
    urls = list(set(re.findall(url_pattern, text, re.IGNORECASE)))
    
    # IP address patterns (IPv4)
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = list(set(re.findall(ip_pattern, text)))
    # Filter out private/invalid IPs
    ips = [ip for ip in ips if is_valid_public_ip(ip)]
    
    # Domain patterns
    domain_pattern = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'
    domains = list(set(re.findall(domain_pattern, text, re.IGNORECASE)))
    # Filter out common non-malicious domains
    domains = [d for d in domains if not is_common_domain(d)]
    
    # Hash patterns (MD5, SHA1, SHA256)
    hash_patterns = [
        r'\b[a-fA-F0-9]{32}\b',  # MD5
        r'\b[a-fA-F0-9]{40}\b',  # SHA1
        r'\b[a-fA-F0-9]{64}\b'   # SHA256
    ]
    hashes = []
    for pattern in hash_patterns:
        hashes.extend(re.findall(pattern, text))
    hashes = list(set(hashes))
    
    # Email patterns
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = list(set(re.findall(email_pattern, text, re.IGNORECASE)))
    
    result = {
        'urls': urls,
        'ips': ips,
        'domains': domains,
        'hashes': hashes,
        'emails': emails
    }
    
    logger.debug(f"Extracted IOCs: {result}")
    return result

def is_valid_public_ip(ip):
    """Check if IP is valid and public"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        
        # Filter out private/reserved IP ranges
        first_octet = int(parts[0])
        second_octet = int(parts[1])
        
        # Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
        if first_octet == 10:
            return False
        if first_octet == 172 and 16 <= second_octet <= 31:
            return False
        if first_octet == 192 and second_octet == 168:
            return False
        
        # Loopback and other reserved ranges
        if first_octet in [127, 169, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239]:
            return False
            
        return True
    except ValueError:
        return False

def is_common_domain(domain):
    """Filter out common non-malicious domains"""
    common_domains = [
        'google.com', 'microsoft.com', 'amazon.com', 'apple.com',
        'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
        'stackoverflow.com', 'wikipedia.org', 'mozilla.org'
    ]
    return any(domain.endswith(common) for common in common_domains)