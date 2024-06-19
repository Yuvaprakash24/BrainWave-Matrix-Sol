import re
import requests
from urllib.parse import urlparse

PHISHING_INDICATORS = [
    r'login',
    r'account',
    r'verify',
    r'update',
    r'password',
    r'security',
    r'bank',
    r'support',
]

LEGITIMATE_DOMAINS = [
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com", "hsbc.com", "usbank.com",
    "paypal.com", "stripe.com", "square.com", "google.com", "bing.com", "yahoo.com", "duckduckgo.com",
    "gmail.com", "outlook.com", "protonmail.com", "facebook.com", "twitter.com", "linkedin.com",
    "instagram.com", "amazon.com", "ebay.com", "etsy.com", "alibaba.com", "walmart.com", "target.com",
    "bestbuy.com", "homedepot.com", "usa.gov", "gov.uk", "canada.ca", "australia.gov.au", "harvard.edu",
    "mit.edu", "stanford.edu", "ox.ac.uk", "cdc.gov", "who.int", "mayoclinic.org", "webmd.com",
    "nytimes.com", "bbc.com", "cnn.com", "reuters.com", "theguardian.com"
]

def fetch_url_content(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            print(f"Failed to fetch URL: {url}")
            return None
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None

def scan_for_phishing(content):
    for indicator in PHISHING_INDICATORS:
        if re.search(indicator, content, re.IGNORECASE):
            return True
    return False

def is_legitimate_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return any(domain.endswith(ld) for ld in LEGITIMATE_DOMAINS)

def scan_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = "http://" + url
    
    if is_legitimate_domain(url):
        return "Safe (Legitimate Domain)"
    
    content = fetch_url_content(url)
    if content:
        if scan_for_phishing(content):
            return "Potential Phishing"
        else:
            return "Safe"
    else:
        return "Unable to Scan"

test_url = input()
result = scan_url(test_url)
print(f"The URL '{test_url}' is classified as: {result}")