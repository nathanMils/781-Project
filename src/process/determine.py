from urllib.parse import urlparse
import re
import whois
import ssl
import socket
from datetime import datetime
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import pandas as pd
import os
import json
import tldextract
import logging
import time
import dns.resolver
import idna
from dotenv import load_dotenv

load_dotenv(dotenv_path='./.env')


logger = logging.getLogger(__name__)


## ADDRESS BAR BASED FEATURES #########################################################

def core_domain(url):
    """Normalize the URL by extracting only the core domain using tldextract."""
    extracted = tldextract.extract(url)
    core_domain = f"{extracted.domain}.{extracted.suffix}"
    return core_domain

def domain_name(url):
    """Normalize the URL by extracting only the domain name using tldextract."""
    extracted = tldextract.extract(url)
    return extracted.domain

def lower_case(url):
    """Normalize the URL by converting it to lowercase."""
    return url.lower()

## RULE: Using the IP Address
## STATUS: FINISHED
def is_having_ip(url):
    """Determines if the URL has an IP address."""
    try:
        hostname = urlparse(url).hostname
        if hostname is None:
            return False
        
        ipv4_pattern = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
        hex_pattern = re.compile(r'^(?:0x[0-9A-Fa-f]{1,2}\.){3}0x[0-9A-Fa-f]{1,2}$')
        
        if ipv4_pattern.match(hostname) or hex_pattern.match(hostname):
            return -1
        return 1
    except Exception:
        return 1

## RULE: Long URL to Hide the Suspicious Part
## STATUS: FINISHED
def is_url_long(url):
    """Determines if the URL length is suspicious or phishing based on length."""
    url_length = len(url)
    
    if url_length < 54:
        return 1  # Legitimate
    elif 54 <= url_length <= 75:
        return 0  # Suspicious
    else:
        return -1  # Phishing
            
    
## RULE: Using URL Shortening Services "TinyURL"
## STATUS: FINISHED
## List of URL shortening services
url_shortening_services = [
    "tinyurl.com", "bit.ly", "t.co", "goo.gl", "is.gd", "buff.ly",
    "adf.ly", "ow.ly", "bit.do", "cutt.ly", "shorte.st", "clck.ru",
    "tiny.cc", "tr.im", "x.co", "soo.gd", "s2r.co", "bl.ink", "mcaf.ee",
    "urlz.fr", "shorturl.at"
]
def is_shortening_service(url):
    """Determines if the URL uses a URL shortening service."""
    core = core_domain(url)
    if core in url_shortening_services:
        return -1
    return 1

## RULE: URL's having "@" Symbol
## STATUS: FINISHED
def is_having_at_symbol(url):
    """Determines if the URL contains an '@' symbol."""
    if '@' in url:
        return -1
    else:
        return 1

## RULE: Redirecting using "//"
## STATUS: FINISHED
def is_double(url):
    """Determines if the URL redirects using '//'."""
    parsed_url = urlparse(url)
    if parsed_url.scheme == "http":
        limit_position = 6
    elif parsed_url.scheme == "https":
        limit_position = 7
    else:
        return 1

    last_occurrence_index = url.rfind("//")

    if last_occurrence_index > limit_position:
        return -1
    else:
        return 1

## RULE: Adding Prefix or Suffix Separated by (-) to the Domain
## STATUS: FINISHED
def is_prefix_suffix(url):
    """Determines if the URL has a prefix or suffix separated by a hyphen."""
    parsed_url = urlparse(url)
    domain_name = parsed_url.netloc

    if '-' in domain_name:
        return -1
    else:
        return 1

## RULE: Sub Domain and Multi Sub Domains
## STATUS: FINISHED
def is_having_sub_domain(url):
    """Classifies a URL based on the number of subdomains."""
    ext = tldextract.extract(url)
    subdomain = ext.subdomain
    num_subdomains = len(subdomain.split('.')) if subdomain else 0
    
    if num_subdomains == 0:
        return 1  # Legitimate
    elif num_subdomains == 1:
        return 1  # Legitimate
    elif num_subdomains == 2:
        return 0  # Suspicious
    else:
        return -1

## RULE: HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer)
## STATUS: FINISHED
## List of trusted Certificate Authorities
TRUSTED_ISSUER_KEYWORDS = {
    "GeoTrust", "GoDaddy", "Network Solutions", "Thawte",
    "Comodo", "Doster", "VeriSign", "DigiCert", "WR2",
    "GlobalSign", "Entrust", "Symantec", "Let's Encrypt",
    "Amazon", "Trustwave", "QuoVadis",
    "SwissSign", "Sectigo", "WoSign", "CNNIC",
    "StartCom", "GeoTrust", "Verisign"
}


def is_trusted_issuer(issuer_common_name):
    return any(keyword in issuer_common_name for keyword in TRUSTED_ISSUER_KEYWORDS)
def is_https(url):
    """Determines if the URL uses HTTPS."""
    try:
        hostname = url.replace("https://", "").replace("http://", "").split('/')[0]

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert['issuer'])
        issuer_common_name = issuer.get('commonName', '')


        if not cert:
            return 1
        

        if not is_trusted_issuer(issuer_common_name):
            return 0


        valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')


        age_in_years = (datetime.now() - valid_from).days / 365.25
        if age_in_years >= 1:
            return 1
        else:
            return 0

    except Exception:
        return -1

## RULE: Domain Registration Length
## STATUS: FINISHED
def is_domain_registration_length(domain):
    """Determines if the URL's domain registration length is suspicious."""
    creation_date = domain.creation_date
    expiration_date = domain.expiration_date

    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

    if creation_date and expiration_date:
        registration_length = (expiration_date - creation_date).days / 365
        if registration_length < 1:
            return -1
        else:
            return 1
    else:
        return -1

## RULE
## STATUS: FINISHED
def is_favicon(url, soup):
    """Determines if the URL has a favicon."""
    
    main_domain = urlparse(url).netloc
    
    favicon_link = soup.find("link", rel=lambda value: value and 'icon' in value.lower())
    
    if not favicon_link or not favicon_link.get("href"):
        return 1
    
    favicon_url = urljoin(url, favicon_link.get("href"))
    favicon_domain = urlparse(favicon_url).netloc
    
    if favicon_domain == main_domain:
        return 1
    else:
        return -1

## RULE: Using Non-Standard Port
## STATUS: FINISHED
## List of preferred ports
preferred_ports = [80, 443]
## List of non-preferred ports
non_preferred_ports = [21, 22, 23, 445, 1433, 1521, 3306, 3389]
def is_port(url):
    """Determines if the URL uses a non-standard port."""
    parsed_url = urlparse(url)
    port = parsed_url.port
    
    if port is None:
        if parsed_url.scheme == 'http':
            port = 80
        elif parsed_url.scheme == 'https':
            port = 443
        else:
            return 1
    
    if port in preferred_ports:
        return 1
    
    elif port in non_preferred_ports:
        return -1
    else:
        return -1


## RULE: HTTP and HTTPS Tokens
## STATUS: FINISHED
def is_https_token(url):
    """Determines if the URL has 'https' tokens."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Check if the "https" token appears in the domain part
    if "https" in domain:
        return -1
    else:
        return 1

########################################################################################
## ABNORMAL BASED FEATURES #############################################################

## RULE: Request URL
## STATUS: FINISHED
def is_request_url(url,soup):
    """Determines if the request URL is legitimate."""
    base_domain = urlparse(url).netloc

    resource_tags = {
        'img': 'src',
        'script': 'src',
        'link': 'href',
        'iframe': 'src',
        'audio': 'src',
        'video': 'src',
        'object': 'data',
    }

    total_resources = 0
    external_resources = 0

    for tag, attribute in resource_tags.items():
        for element in soup.find_all(tag):
            resource = element.get(attribute)
            if resource:
                total_resources += 1
                resource_url = urljoin(url, resource)
                resource_domain = urlparse(resource_url).netloc

                if resource_domain and resource_domain != base_domain:
                    external_resources += 1

    if total_resources == 0:
        return 1

    external_percentage = (external_resources / total_resources) * 100

    if external_percentage < 22:
        return 1
    elif 22 <= external_percentage < 61:
        return 0
    else:
        return -1

## RULE: URL of Anchor
## STATUS: FINISHED
def is_url_of_anchor(url, soup):
    """Determines if the URL of the anchor is suspicious."""
    website_domain = urlparse(url).netloc

    anchor_tags = soup.find_all('a')
    different_domain_count = 0
    total_count = 0

    for anchor in anchor_tags:
        href = anchor.get('href', '')
        if href in ['#', '#content', '#skip', 'JavaScript::void(0)', '']:
            continue
    
        anchor_url = urlparse(href)
        
        # If the anchor URL has a netloc (i.e., it is a full URL), compare the domains
        if anchor_url.netloc:
            if anchor_url.netloc != website_domain:
                different_domain_count += 1
        
        total_count += 1

    if total_count == 0:
        return 1
    
    # Calculate the percentage of anchors with different domains
    domain_percentage = (different_domain_count / total_count) * 100

    # Apply the classification rule
    if domain_percentage < 31:
        return 1
    elif 31 <= domain_percentage <= 67:
        return 0
    else:
        return -1

## RULE: Links in Meta, Script and Link Tags
## STATUS: FINISHED
def is_links_in_tags(url, soup):
    """Determines if the links in meta, script, and link tags are suspicious."""
    base_domain = urlparse(url).netloc
    total_links = 0
    external_links = 0
    tags_to_check = soup.find_all(['meta', 'script', 'link'])
    for tag in tags_to_check:
        href_or_src = tag.get('href') or tag.get('src')
        if href_or_src:
            total_links += 1
            full_url = urljoin(url, href_or_src)
            external_domain = urlparse(full_url).netloc
            if external_domain and external_domain != base_domain:
                external_links += 1
    if total_links == 0:
        return 1

    external_percentage = (external_links / total_links) * 100

    if external_percentage < 17:
        return 1
    elif 17 <= external_percentage <= 81:
        return 0
    else:
        return -1

## RULE: Server Form Handler (SFH)
## STATUS: FINISHED
def is_sfh(url, soup):
    """Determines if the server form handler is suspicious."""
    base_domain = urlparse(url).netloc

    forms = soup.find_all('form')
    
    for form in forms:
        sfh = form.get('action')
        
        if not sfh:
            return -1
        
        full_sfh = urljoin(url, sfh)
        action_domain = urlparse(full_sfh).netloc
        
        if sfh == "" or sfh == "about:blank":
            return 1
        if action_domain != base_domain:
            return 0
    
    return 1

## RULE: Submitting Information to Email
## STATUS: FINISHED
def is_submitting_to_email(response, soup):
    """Determines if the URL submits information to an email."""
    if 'mail()' in response.text:
        return -1
    
    for form in soup.find_all('form'):
        action = form.get('action', '')
        if 'mailto:' in action:
            return -1
    
    for link in soup.find_all('a'):
        href = link.get('href', '')
        if 'mailto:' in href:
            return -1

    return 1

def is_submitting_to_email_direct(html, soup):
    """Determines if the URL submits information to an email."""
    if 'mail()' in html:
        return -1
    
    for form in soup.find_all('form'):
        action = form.get('action', '')
        if 'mailto:' in action:
            return -1
    
    for link in soup.find_all('a'):
        href = link.get('href', '')
        if 'mailto:' in href:
            return -1

    return 1


## RULE: Abnormal URL
## STATUS: FINISHED
def is_abnormal_url(url):
    """Determines if the URL is abnormal."""
    ext = tldextract.extract(url)
    host_name = ext.domain + '.' + ext.suffix
    w = whois.whois(url)
    if w and 'domain_name' in w:
        domain_names = w['domain_name']
        logging.info(f"Domain names: {domain_names}")
        if isinstance(domain_names, list):
            for domain in domain_names:
                if host_name.lower() == domain.lower():
                    return 1
        elif isinstance(domain_names, str):
            if host_name.lower() == domain_names.lower():
                return 1
    return -1


########################################################################################
## HTML AND JAVASCRIPT BASED FEATURES ##################################################

## RULE: Website Forwarding
## STATUS: FINISHED
def is_redirect(response):
    """Determines if the URL forwards to another URL."""
    num_redirects = len(response.history)
        
    # Apply the rule based on the number of redirects
    if num_redirects <= 1:
        return 1
    elif 2 <= num_redirects < 4:
        return 0
    else:
        return -1

## RULE: Status Bar Customization
## STATUS: FINISHED
def is_on_mouseover(soup):
    """Determines if the URL has status bar customization."""
    onmouseover_events = soup.find_all(attrs={"onmouseover": True})
        
    for event in onmouseover_events:
        if re.search(r'window\.status', event['onmouseover']):
            return -1
    return 1

## RULE: Disabling Right Click
## STATUS: FINISHED
def is_rightclick(soup):
    """Determines if the URL disables right-clicking."""
    script_tags = soup.find_all('script', string=True)
    for script in script_tags:
        if re.search(r'event\.button\s*==\s*2', script.string) or re.search(r'contextmenu', script.string):
            return -1
    return 1

## RULE: Pop-up Windows
## STATUS: FINISHED
def is_popupwindow(soup):
    """Determines if the URL uses pop-up windows."""
    pop_up_scripts = soup.find_all('script', string=re.compile('window\.open', re.IGNORECASE))
    input_elements = soup.find_all(['input', 'textarea', 'select'])
    
    for pop_up_script in pop_up_scripts:
        if any(input_elem in pop_up_script for input_elem in input_elements):
            return -1
    
    return 1

## RULE: IFrame Redirection
## STATUS: FINISHED
def is_iframe(soup):
    """Determines if the URL uses an iframe."""
    if soup.find_all('iframe'):
        return -1
    return 1

########################################################################################
## DOMAIN BASED FEATURES ###############################################################

## RULE: Age of Domain
## STATUS: FINISHED
def is_age_of_domain(domain):
    """Determines if the URL's domain age is suspicious."""
    if domain.creation_date:
        if isinstance(domain.creation_date, list):
            creation_date = domain.creation_date[0]
        else:
            creation_date = domain.creation_date

        current_date = datetime.now()

        age_in_months = (current_date.year - creation_date.year) * 12 + current_date.month - creation_date.month

        if age_in_months >= 6:
            return 1
        else:
            return -1
    else:
        return -1

## RULE: DNS Record
## STATUS: FINISHED
def is_dns_record(url, timeout=5):
    """Check if the domain or subdomain has DNS records."""
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout  # Set a timeout for the entire resolution process
    
    try:
        a_records = resolver.resolve(domain, 'A')
        if a_records:
            return 1
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        return -1
    except dns.exception.Timeout:
        return -1
    except dns.resolver.NoNameservers:
        return -1
    
    try:
        aaaa_records = resolver.resolve(domain, 'AAAA')
        if aaaa_records:
            return 1
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        return -1
    except dns.exception.Timeout:
        return -1
    except dns.resolver.NoNameservers:
        return -1
    
    return -1

## RULE: Web Traffic
## STATUS: FINISHED
def is_web_traffic(data):
    """Determines if the URL has suspicious web traffic."""
    if data is None:
        return -1

    entry = data['response'][0]  # Assuming there's always one entry
    global_rank = entry['rank']
        
    if global_rank is not None:
        global_rank = int(global_rank)
        if global_rank < 100000:
            return 1
        else:
            return 0
    else:
        return -1
    
def get_open_page_rank(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        url = "https://openpagerank.com/api/v1.0/getPageRank"
        params = {
            "domains[]": domain
        }

        headers = {
            "API-OPR": os.getenv('OPEN_PAGE_RANK_API_KEY')
        }

        response = requests.get(url, params=params, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception:
        logging.error(f"Error occurred while fetching Open Page Rank for domain: {domain}")
        return None

## RULE: Page Rank
## STATUS: FINISHED
def is_page_rank(data):
    """Determines if the URL has a suspicious page rank."""
    page_rank = data.get('response', [{}])[0].get('page_rank_decimal', None)
    
    if page_rank is None:
        return -1
    elif page_rank < 0.2:
        return -1
    else:
        return 1


SERP_API_KEY = os.getenv('SERP_API_KEY')

def is_website_indexed(url):
    """
    Checks if a specific URL is indexed by Google using SerpAPI.
    
    :param url: The full URL to check for indexing.
    :return: True if indexed, False otherwise.
    """
    try:
        parsed_url = urlparse(url)
        full_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        query = f"site:{full_url}"
        
        api_url = "https://google.serper.dev/search"
        payload = json.dumps({"q": query})
        headers = {
            'X-API-KEY': SERP_API_KEY,
            'Content-Type': 'application/json'
        }

        response = requests.post(api_url, headers=headers, data=payload)

        if response.status_code == 200:
            results = response.json()
            if results.get("organic", []):
                return 1
            else:
                return -1
        else:
            logging.error(f"API request failed with status {response.status_code}: {response.text}")
            if (response.status_code == 403):
                return "STOP"
            
            if (response.status_code == 429):
                time.sleep(20)
                return is_website_indexed(url)
            return 1
    except Exception as e:
        logging.error(f"Error occurred while checking Google Index for URL: {url}, error: {e}")
        return 1

# RULE: Google Index UPDATE
# STATUS: FINISHED
def is_google_index(url):
    """Determines if the URL is indexed by Google."""

    return is_website_indexed(url)

## RULE: Number of Links Pointing to Page
## STATUS: FINISHED
def is_links_pointing_to_page(url, soup):
    """Determines if the URL has a suspicious number of links pointing to the page."""

    links = soup.find_all('a', href=True)
    domain = urlparse(url).netloc
    external_links_count = 0
    for link in links:
        href = link.get('href')
        if href:
            href_domain = urlparse(href).netloc
            if href_domain and href_domain != domain:
                external_links_count += 1

    if external_links_count == 0:
        return -1
    elif 0 < external_links_count <= 2:
        return 0
    else:
        return 1

## RULE: Statistical Reports
## STATUS: FINISHED
## List of top phishing domains and IPs
# CloudFlare
top_phishing_tlds = [
    # Cheap and Open TLDs
    ".xyz", ".top", ".club", ".online", ".shop", ".site", ".vip", ".buzz",

    # Freenom TLDs (Free Domains)
    ".tk", ".ml", ".ga", ".cf", ".gq",

    # Geographic and Niche TLDs less commonly used for legitimate purposes
    ".ly", ".to", ".ru", ".cn", ".su"
]

def is_statistical_report(url):
    """Determines if the URL has a suspicious statistical report based on phishing domains or IPs."""
    ext = tldextract.extract(url)
    if f".{ext.suffix}" in top_phishing_tlds:
        return -1  # Phishing
    
    return 1

########################################################################################
## ADDED FEATURES ######################################################################


## BRAND IMPERSONATION BASED FEATURES ##################################################
# 1. Presence of Numbers in the Domain
def has_numbers_in_domain(url: str) -> bool:
    domain = urlparse(url).netloc
    if bool(re.search(r'\d', domain)):
        return 0
    return 1

# 2. Presence of Special Characters in the Domain
def has_special_characters_in_domain(url: str) -> bool:
    domain = urlparse(url).netloc
    special_chars = set("!#$%&'()*+,/:;<=>?@[\\]^`{|}~")
    if any(char in special_chars for char in domain):
        return 0
    return 1

# 3. Presence of IDN Spoofing in the Domain
HOMOGLYPHS = {
    'a': ['α', 'а'],  # Latin 'a' vs Greek 'alpha' and Cyrillic 'a'
    'o': ['ο', 'օ'],  # Latin 'o' vs Greek 'omicron' and Armenian 'o'
    'e': ['е'],       # Latin 'e' vs Cyrillic 'e'
    'i': ['і', '١'],   # Latin 'i' vs Cyrillic 'і' and Arabic digit '1'
    'l': ['ӏ', '١'],   # Latin 'l' vs Cyrillic 'ӏ' and Arabic digit '1'
    'u': ['υ'],       # Latin 'u' vs Greek 'upsilon'
    'c': ['с'],       # Latin 'c' vs Cyrillic 'с'
    'n': ['п'],       # Latin 'n' vs Cyrillic 'п'
}

## NOT USED NOT ENOUGH DATA TO BE AFFECTIVE
def homoglyph(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        is_idn = not domain.isascii()
        suspicious_chars = []

        if is_idn:
            for char in domain:
                for key, glyphs in HOMOGLYPHS.items():
                    if char in glyphs:
                        suspicious_chars.append((char, key))
            
            if suspicious_chars:
                return -1
            else:
                return 0
        else:
            return 1
    except Exception as e:
        print(f"Error parsing URL: {e}")
        return 1
    
# 4. Presence of Brand Name in the Domain - CUSTOM Approach

KNOWN_BRANDS_DOMAINS = [
    "microsoft",
    "apple",
    "google",
    "facebook",
    "whatsapp",
    "amazon",
    "alibaba",
    "adobe",
    "twitter",
    "adidas",
    "netflix",
    "paypal",
    "bankofamerica",
    "chase",
    "wellsfargo",
    "linkedin",
    "ebay",
    "instagram",
    "zoom",
    "dropbox",
    "youtube",
    "airbnb",
    "spotify",
    "appleid"
]

import Levenshtein

def extract_domain_and_subdomains(url):
    """
    Extract the domain, subdomains, and TLD from a given URL using tldextract.
    """
    extracted = tldextract.extract(url)
    subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
    domain = extracted.domain
    return domain, subdomains

def overlapping_substrings(string, n):
    """
    Breaks the string into overlapping substrings of length n with a stride of 1.
    If there are fewer than n characters remaining at the end, it takes the remaining characters.
    """
    substrings = []
    for i in range(len(string) - n + 1):
        substrings.append(string[i:i + n])
    
    if len(string) - (len(string) - n + 1) > 0:
        substrings.append(string[-n:])
    
    return substrings

def check_brands(url, brand_name="microsoft"):
    """
    Analyzes the URL for phishing indicators based on domain and subdomain similarity to brand name.
    Uses Levenshtein distance normalized by the length of the target brand name.
    """
    domain, subdomains = extract_domain_and_subdomains(url)
    domain_and_subdomains = ''.join(sub.replace('.', '') for sub in subdomains) + domain.replace('.', '')
    brand_len = len(brand_name)
    domain_substrings = overlapping_substrings(domain_and_subdomains, brand_len)
    domain_levenshtein_distances = [Levenshtein.distance(sub, brand_name) for sub in domain_substrings]
    
    min_distance = min(domain_levenshtein_distances)
    normalized_distance = min_distance / brand_len
    return normalized_distance

def is_brand_impersonation_lev(url):
    """
    Determines if the URL is impersonating a known brand.
    """
    domain, _ = extract_domain_and_subdomains(url)
    if domain in KNOWN_BRANDS_DOMAINS:
        return 1, 1
    current = 1
    current_similarity = 100
    for brand in KNOWN_BRANDS_DOMAINS:
        distance = check_brands(url, brand)
        if distance < 0.2:
            return -1, distance
        elif distance < current_similarity:
            current = 0
            current_similarity = distance

    return current, current_similarity

from fuzzywuzzy import fuzz

def is_brand_impersonation_fuzzy(url):
    """
    Analyzes the URL for phishing indicators based on domain and subdomain similarity to brand name.
    Uses fuzzy matching (Levenshtein distance) to compare strings.
    """
    domain, subdomains = extract_domain_and_subdomains(url)
    if domain in KNOWN_BRANDS_DOMAINS:
        return 1, 0
    current = 1
    current_similarity = 0
    for brand in KNOWN_BRANDS_DOMAINS:
        similarity = fuzz.ratio(domain, brand)
        if similarity > 70:
            return -1, similarity
        elif similarity > 50:
            current = 0
            current_similarity = max(current_similarity, similarity)
    
    if subdomains == []:
        return current, current_similarity
    
    for brand in KNOWN_BRANDS_DOMAINS:
        for subdomain in subdomains:
            similarity = fuzz.ratio(subdomain, brand)
            if similarity > 70:
                return -1, similarity
            elif similarity > current_similarity:
                current = 0
                current_similarity = similarity
    return current, current_similarity

def num_subdomains(url):
    _, subdomains = extract_domain_and_subdomains(url)
    if subdomains is None:
        return 1, 0
    if len(subdomains) in {0, 1}:
        return 1, len(subdomains)
    elif len(subdomains) > 1:
        return -1, len(subdomains)

def length_of_subdomains(url):
    subdomains = tldextract.extract(url).subdomain
    if subdomains is None:
        return 1, 0
    length = len(subdomains)
    if len(subdomains) < 8:
        return 1, length
    elif 8 <= len(subdomains) <= 15:
        return 0, length
    else:
        return -1, length

########################################################################################




########################################################################################

def check_if_valid(url):
    """Checks if the URL is valid."""
    try:
        parsed_url = urlparse(url)
        return all([parsed_url.scheme, parsed_url.netloc])
    except Exception:
        return False
    
def check_if_reachable(url):
    """Checks if the URL is reachable."""
    try:
        response = requests.get(url)
        return response
    except Exception:
        return False
    
# May adjust such that local extension sends html content directly, more accurate and more efficient
def parse_html(response):
    """Parses the HTML content of a URL."""
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup
    except Exception:
        return False
    
def parse_html_direct(html):
    """Parses the HTML content of a URL."""
    try:
        soup = BeautifulSoup(html, 'html.parser')
        return soup
    except Exception:
        return False
    
def get_whois(url):
    """Gets the WHOIS information of a URL."""
    try:
        domain = whois.whois(url)
        return domain
    except Exception:
        return False
    
def validate_value(value):
    """Ensures the value is either 0, -1, or 1. Returns None if not."""
    if value in {0, -1, 1}:
        return value
    return None
    
def collect_data(url, html): 
    """Determines if a URL is a phishing website or not."""
    if not check_if_valid(url):
        logging.error(f"Invalid URL: {url}")
        return None
    response = check_if_reachable(url)
    if not response:
        logging.error(f"Unreachable URL: {url}")
        return None
    soup = parse_html_direct(html)
    if not soup:
        logging.error(f"Error parsing HTML content for URL: {url}")
        return None
    domain = get_whois(url)
    if not domain:
        logging.error(f"Error fetching WHOIS information for URL: {url}")
        return None
    
    open_page_rank = get_open_page_rank(url)
    logging.info(f"Page rank data: {open_page_rank}")

    lev, sim_lev = is_brand_impersonation_lev(url)
    fuzz, sim_fuzz = is_brand_impersonation_fuzzy(url)

    num_sub, num_of_subdomains = num_subdomains(url)
    len_sub, len_of_subdomains = length_of_subdomains(url)

    data = {
        "website_url": url,
        "having_ip_address": is_having_ip(url),
        "url_length": is_url_long(url),
        "shortining_service": is_shortening_service(url),
        "having_at_symbol": is_having_at_symbol(url),
        "double_slash_redirecting": is_double(url),
        "prefix_suffix": is_prefix_suffix(url),
        "having_sub_domain": is_having_sub_domain(url),
        "sslfinal_state": is_https(url),
        "domain_registration_length": is_domain_registration_length(domain),
        "favicon": is_favicon(url, soup),
        "port": is_port(url),
        "https_token": is_https_token(url),
        "request_url": is_request_url(url, soup),
        "url_of_anchor": is_url_of_anchor(url, soup),
        "links_in_tags": is_links_in_tags(url, soup),
        "sfh": is_sfh(url, soup),
        "submitting_to_email": is_submitting_to_email_direct(html, soup),
        "abnormal_url": is_abnormal_url(url),
        "redirect": is_redirect(response),
        "on_mouseover": is_on_mouseover(soup),
        "rightclick": is_rightclick(soup),
        "popupwindow": is_popupwindow(soup),
        "iframe": is_iframe(soup),
        "age_of_domain": is_age_of_domain(domain),
        "dnsrecord": is_dns_record(url),
        "web_traffic": is_web_traffic(open_page_rank),
        "page_rank": is_page_rank(open_page_rank),
        "google_index": is_google_index(url),
        "links_pointing_to_page": is_links_pointing_to_page(url, soup),
        "statistical_report": is_statistical_report(url),
        "has_numbers": has_numbers_in_domain(url),
        "special_characters": has_special_characters_in_domain(url),
        "lev": lev,
        "sim_lev": sim_lev,
        "fuzzy": fuzz,
        "sim_fuzz": sim_fuzz,
        "num_sub": num_sub,
        "num_of_subdomains": num_of_subdomains,
        "len_sub": len_sub,
        "len_of_subdomains": len_of_subdomains,
        "result": 1
    }

    for key, value in data.items():
        if key in {"website_url", "sim_lev", "sim_fuzz", "num_of_subdomains", "len_of_subdomains"}:
            continue
        validated_value = validate_value(value)
        if validated_value is None:
            data = None
            break
        data[key] = validated_value
    return open_page_rank, data

# [
#     "page_rank_decimal",
#     "url_length",
#     "double_slash_redirecting",
#     "prefix_suffix",
#     "favicon",
#     "request_url",
#     "url_of_anchor",
#     "links_in_tags",
#     "sfh",
#     "submitting_to_email",
#     "abnormal_url",
#     "redirect",
#     "popupwindow",
#     "iframe",
#     "web_traffic",
#     "page_rank",
#     "google_index",
#     "links_pointing_to_page",
#     "has_numbers",
#     "lev",
#     "sim_lev",
#     "fuzzy",
#     "sim_fuzz",
#     "num_of_subdomains",
#     "len_sub",
#     "len_of_subdomains"
# ]

def calculate(url, html):
    """Determines if a URL is a phishing website or not."""
    if not check_if_valid(url):
        logging.error(f"Invalid URL: {url}")
        return None
    response = check_if_reachable(url)
    if not response:
        logging.error(f"Unreachable URL: {url}")
        return None
    soup = parse_html_direct(html)
    if not soup:
        logging.error(f"Error parsing HTML content for URL: {url}")
        return None
    domain = get_whois(url)
    if not domain:
        logging.error(f"Error fetching WHOIS information for URL: {url}")
        return None
    
    open_page_rank = get_open_page_rank(url)
    logger.info(f"Page rank data: {open_page_rank}")
    
    lev, sim_lev = is_brand_impersonation_lev(url)
    fuzz, sim_fuzz = is_brand_impersonation_fuzzy(url)

    num_sub, num_of_subdomains = num_subdomains(url)
    len_sub, len_of_subdomains = length_of_subdomains(url)

    data = {
        "page_rank_decimal": is_page_rank(open_page_rank),
        "url_length": is_url_long(url),
        "double_slash_redirecting": is_double(url),
        "prefix_suffix": is_prefix_suffix(url),
        "favicon": is_favicon(url, soup),
        "request_url": is_request_url(url, soup),
        "url_of_anchor": is_url_of_anchor(url, soup),
        "links_in_tags": is_links_in_tags(url, soup),
        "sfh": is_sfh(url, soup),
        "submitting_to_email": is_submitting_to_email_direct(html, soup),
        "abnormal_url": is_abnormal_url(url),
        "redirect": is_redirect(response),
        "popupwindow": is_popupwindow(soup),
        "iframe": is_iframe(soup),
        "web_traffic": is_web_traffic(open_page_rank),
        "page_rank": is_page_rank(open_page_rank),
        "google_index": is_google_index(url),
        "links_pointing_to_page": is_links_pointing_to_page(url, soup),
        "has_numbers": has_numbers_in_domain(url),
        "lev": lev,
        "sim_lev": sim_lev,
        "fuzzy": fuzz,
        "sim_fuzz": sim_fuzz,
        "num_of_subdomains": num_of_subdomains,
        "len_sub": len_sub,
        "len_of_subdomains": len_of_subdomains,
    }

    for key, value in data.items():
        if key in {"website_url", "sim_lev", "sim_fuzz", "num_of_subdomains", "len_of_subdomains"}:
            continue
        validated_value = validate_value(value)
        if validated_value is None:
            data = None
            break
        data[key] = validated_value
    return data
