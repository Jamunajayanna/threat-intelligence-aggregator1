import requests
import feedparser
import logging
import json
from extract_iocs import extract_iocs
from llm_service import llm_service

logger = logging.getLogger(__name__)

# Separate JSON & RSS/Atom feeds
THREATFOX_JSON_URLS = [
    "https://threatfox.abuse.ch/export/json/urls/recent/",
    "https://threatfox.abuse.ch/export/json/sha256/recent/",
    "https://threatfox.abuse.ch/export/json/ip-port/recent/",
]

RSS_FEEDS = [
    "https://otx.alienvault.com/feed/",
    "https://feeds.feedburner.com/eset/blog",
    "https://blog.talosintelligence.com/feeds/posts/default",
    "https://www.fireeye.com/blog/threat-research/_jcr_content.feed",
    "https://blog.malwarebytes.com/feed/",
    "https://www.proofpoint.com/us/rss.xml",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://www.crowdstrike.com/blog/feed/",
    "https://www.microsoft.com/security/blog/feed/",
    "https://blog.checkpoint.com/feed/",
]

# GitHub threat intelligence repositories
GITHUB_FEEDS = [
    "https://github.com/MISP/misp-objects/commits/main.atom",
    "https://github.com/stamparm/maltrail/commits/master.atom",
    "https://github.com/Neo23x0/signature-base/commits/master.atom",
    "https://github.com/blackorbird/APT_REPORT/commits/master.atom",
    "https://github.com/Yara-Rules/rules/commits/master.atom",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; ThreatIntelBot/1.0)"
}

def summarize_threat(text):
    """
    Summarize threat using available LLM backends (Ollama, OpenAI, or enhanced fallback)
    """
    return llm_service.summarize_threat(text)

def fetch_threat_iocs():
    """Fetch threat intelligence from various sources"""
    entries = []
    
    # Handle JSON Feeds (like ThreatFox)
    for url in THREATFOX_JSON_URLS:
        try:
            logger.info(f"Fetching JSON: {url}")
            r = requests.get(url, headers=HEADERS, timeout=10)
            if r.status_code == 200:
                try:
                    data = r.json()
                    logger.debug(f"Raw JSON response structure: {type(data)}")
                    
                    # ThreatFox API returns different structures
                    if isinstance(data, list):
                        # Direct list of IOCs
                        for item in data:
                            process_threatfox_item(item, entries)
                    elif isinstance(data, dict):
                        # Dictionary with nested data
                        for key, value in data.items():
                            if isinstance(value, list):
                                for item in value:
                                    process_threatfox_item(item, entries)
                            elif isinstance(value, dict):
                                process_threatfox_item(value, entries)
                    
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error for {url}: {e}")
                    
        except requests.RequestException as e:
            logger.error(f"Request error for {url}: {e}")
        except Exception as e:
            logger.error(f"ThreatFox fetch error for {url}: {e}")
    
    # Handle RSS Feeds and GitHub Feeds
    all_feeds = RSS_FEEDS + GITHUB_FEEDS
    for feed_url in all_feeds:
        try:
            logger.info(f"Parsing feed: {feed_url}")
            feed = feedparser.parse(feed_url)
            source_name = get_source_name(feed_url)
            
            if hasattr(feed, 'entries'):
                for entry in feed.entries[:5]:  # Limit to 5 entries per feed
                    content = entry.get("summary", "") + " " + entry.get("title", "")
                    iocs = extract_iocs(content)
                    
                    # Process entries with IOCs or security-relevant content
                    if any(iocs.values()) or is_security_relevant(content, entry.get("title", "")):
                        summary_text = summarize_threat(content)
                        entries.append({
                            "title": entry.get("title", "Security Alert"),
                            "link": entry.get("link", "#"),
                            "published": entry.get("published", "N/A"),
                            "summary": summary_text,
                            "iocs": iocs,
                            "source": source_name,
                            "threat_type": detect_threat_type(content, entry.get("title", "")),
                            "malware": detect_malware_family(content, entry.get("title", ""))
                        })
                        
        except Exception as e:
            logger.error(f"Feed fetch error for {feed_url}: {e}")
    
    logger.info(f"Total entries processed: {len(entries)}")
    return entries

def process_threatfox_item(item, entries):
    """Process a single ThreatFox item"""
    try:
        if not isinstance(item, dict):
            return
            
        # Extract IOC value from different possible fields
        ioc_value = (item.get("ioc_value") or 
                    item.get("ioc") or 
                    item.get("url") or 
                    item.get("malware_printable") or 
                    item.get("reference") or 
                    str(item))
        
        if ioc_value:
            iocs = extract_iocs(str(ioc_value))
            if any(iocs.values()):
                summary_text = summarize_threat(str(ioc_value))
                entries.append({
                    "title": f"IOC Detected ({item.get('ioc_type', 'Unknown')})",
                    "link": item.get("reference", "#"),
                    "published": item.get("first_seen_utc", "N/A"),
                    "summary": summary_text,
                    "iocs": iocs,
                    "threat_type": item.get("threat_type", "Unknown"),
                    "malware": item.get("malware_printable", "Unknown")
                })
                
    except Exception as e:
        logger.error(f"Error processing ThreatFox item: {e}")

def get_source_name(feed_url):
    """Extract source name from feed URL"""
    if "github.com" in feed_url:
        return "GitHub Intelligence"
    elif "otx.alienvault.com" in feed_url:
        return "AlienVault OTX"
    elif "eset" in feed_url:
        return "ESET Research"
    elif "talosintelligence" in feed_url:
        return "Cisco Talos"
    elif "fireeye" in feed_url:
        return "FireEye"
    elif "malwarebytes" in feed_url:
        return "Malwarebytes"
    elif "proofpoint" in feed_url:
        return "Proofpoint"
    elif "paloaltonetworks" in feed_url:
        return "Unit 42"
    elif "crowdstrike" in feed_url:
        return "CrowdStrike"
    elif "microsoft" in feed_url:
        return "Microsoft Security"
    elif "checkpoint" in feed_url:
        return "Check Point"
    else:
        return "Security Feed"

def is_security_relevant(content, title):
    """Check if content is security-relevant"""
    text = (content + " " + title).lower()
    security_keywords = [
        'malware', 'threat', 'vulnerability', 'exploit', 'attack', 'breach',
        'ransomware', 'phishing', 'botnet', 'trojan', 'apt', 'campaign',
        'ioc', 'indicator', 'compromise', 'security', 'cyber', 'backdoor'
    ]
    return any(keyword in text for keyword in security_keywords)

def detect_threat_type(content, title):
    """Detect threat type from content"""
    text = (content + " " + title).lower()
    if any(word in text for word in ['botnet', 'c2', 'command']):
        return 'botnet_cc'
    elif any(word in text for word in ['payload', 'delivery', 'download']):
        return 'payload_delivery'
    elif any(word in text for word in ['phishing', 'scam']):
        return 'phishing'
    elif any(word in text for word in ['ransomware', 'crypto']):
        return 'ransomware'
    else:
        return 'mixed'

def detect_malware_family(content, title):
    """Detect malware family from content"""
    text = (content + " " + title).lower()
    families = {
        'stealc': 'Stealc',
        'emotet': 'Emotet',
        'trickbot': 'TrickBot',
        'dridex': 'Dridex',
        'qakbot': 'QakBot',
        'cobalt strike': 'Cobalt Strike',
        'redline': 'RedLine',
        'vidar': 'Vidar',
        'amadey': 'Amadey',
        'raccoon': 'Raccoon'
    }
    
    for family_key, family_name in families.items():
        if family_key in text:
            return family_name
    
    return 'Various'