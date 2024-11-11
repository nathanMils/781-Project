from urllib.parse import urlparse
import re
import whois
from datetime import datetime

# Helper functions
from ssl import get_certificate_info
# from favicon import get_favicon_domain

import logging

logger = logging.getLogger('process.determine')


def is_phishing(model, url):
    """Determines if a URL is a phishing website or not."""
    # Placeholder for actual implementation
    pass

## ADDRESS BAR BASED FEATURES #########################################################

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
            logger.debug(f"URL: {url} is having an IP address.")
            return -1
        logger.debug(f"URL: {url} is not having an IP address.")
        return 1
    except Exception:
        logger.error(f"Error occurred while determining if the URL: {url} is having an IP address.")
        return 1

## RULE: Long URL to Hide the Suspicious Part
## STATUS: FINISHED
def is_url_long(url):
    """Determines if the URL length is suspicious."""
    try:
        url_length = len(url)
        if url_length >= 54:
            logger.debug(f"URL: {url} is suspiciously long with length {url_length}.")
            return -1
        logger.debug(f"URL: {url} is not suspiciously long with length {url_length}.")
        return 1
    except Exception:
        logger.error(f"Error occurred while determining if the URL: {url} is suspiciously long.")
        return 1
    
## RULE: Using URL Shortening Services "TinyURL"
## STATUS: FINISHED
## List of URL shortening services
url_shortening_services = [
    "tinyurl.com", "bit.ly", "t.co", "goo.gl", "is.gd", "buff.ly",
    "adf.ly", "ow.ly", "bit.do", "cutt.ly", "shorte.st", "clck.ru",
    "tiny.cc", "tr.im", "x.co", "soo.gd", "s2r.co", "bl.ink", "mcaf.ee"
]
def is_shortening_service(url):
    """Determines if the URL uses a URL shortening service."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    if domain in url_shortening_services:
        return -1
    else:
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
## List Common Top Level Domains
common_tlds = [
    'com', 'net', 'org', 'uk', 'edu', 'gov', 'info', 'biz', 'co', 'us', 'ca', 
    'de', 'za', 'fr', 'au', 'ru', 'ch', 'it', 'nl', 'se', 'no', 'es', 'mil', 
    'int', 'eu', 'cn', 'in', 'br', 'za', 'mx', 'kr', 'hk', 'sg', 'tv', 'me'
]
def is_having_sub_domain(url):
    """Determines if the URL has multiple subdomains."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]
    domain = domain.lstrip('www.')
    domain_parts = domain.split('.')
    if domain_parts[-1] in common_tlds:
        domain_parts = domain_parts[:-1]
    num_dots = len(domain_parts) - 1

    if num_dots == 1:
        return 0
    elif num_dots == 0:
        return 1
    else:
        return -1

## RULE: HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer)
## STATUS: FINISHED
## List of trusted Certificate Authorities
trusted_cas = ['GeoTrust', 'GoDaddy', 'Network Solutions', 'Thawte', 'Comodo', 'Doster', 'VeriSign']
def is_https(url):
    """Determines if the URL uses HTTPS."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]

    if parsed_url.scheme != 'https':
        return -1
    
    certificate_issuer, certificate_age = get_certificate_info(domain)

    if certificate_issuer is None or certificate_age is None:
        return -1

    if certificate_issuer in trusted_cas and certificate_age >= 1:
        return 1
    elif certificate_issuer not in trusted_cas:
        return 0
    else:
        return -1


TODAY = datetime.now()

## RULE: Domain Registration Length
## STATUS: FINISHED
def is_domain_registration_length(url):
    """Determines if the URL's domain registration length is suspicious."""
    try:
        domain = whois.whois(url)
        creation_date = domain.creation_date
        expiration_date = domain.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date and expiration_date:
            registration_length = (expiration_date - creation_date).days / 365
            if registration_length < 1:
                logger.debug(f"URL: {url} has a suspicious domain registration length of {registration_length} years.")
                return -1
            else:
                logger.debug(f"URL: {url} has a domain registration length of {registration_length} years.")
                return 1
        else:
            logger.debug(f"URL: {url} does not have valid creation or expiration dates.")
            return "ERROR"
    except Exception as e:
        logger.error(f"Error occurred while determining the domain registration length for URL: {url}. Exception: {e}")
        return "UNKNOWN"

## RULE: Favicon
## STATUS: NOT DONE
def is_favicon(url):
    """Determines if the URL has a favicon."""
    favicon_domain, page_domain = get_favicon_domain(url)
    
    if favicon_domain is None:
        return 1
    
    if favicon_domain != page_domain:
        return -1
    
    return 1

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
## STATUS: NOT STARTED
def is_request_url(url):
    """Determines if the request URL is legitimate."""
    # Placeholder for actual implementation
    pass

## RULE: URL of Anchor
## STATUS: NOT STARTED
def is_url_of_anchor(url):
    """Determines if the URL of the anchor is suspicious."""
    # Placeholder for actual implementation
    pass

## RULE: Links in Meta, Script and Link Tags
## STATUS: NOT STARTED
def is_links_in_tags(url):
    """Determines if the links in meta, script, and link tags are suspicious."""
    # Placeholder for actual implementation
    pass

## RULE: Server Form Handler (SFH)
## STATUS: NOT STARTED
def is_sfh(url):
    """Determines if the server form handler is suspicious."""
    # Placeholder for actual implementation
    pass

## RULE: Submitting Information to Email
## STATUS: NOT STARTED
def is_submitting_to_email(url):
    """Determines if the URL submits information to an email."""
    # Placeholder for actual implementation
    pass

## RULE: Abnormal URL
## STATUS: NOT STARTED
def is_abnormal_url(url):
    """Determines if the URL is abnormal."""
    # Placeholder for actual implementation
    pass


########################################################################################
## HTML AND JAVASCRIPT BASED FEATURES ##################################################

## RULE: Website Forwarding
## STATUS: NOT STARTED
def is_redirect(url):
    """Determines if the URL forwards to another URL."""
    # Placeholder for actual implementation
    pass

## RULE: Status Bar Customization
## STATUS: NOT STARTED
def is_on_mouseover(url):
    """Determines if the URL has status bar customization."""
    # Placeholder for actual implementation
    pass

## RULE: Disabling Right Click
## STATUS: NOT STARTED
def is_rightclick(url):
    """Determines if the URL disables right-clicking."""
    # Placeholder for actual implementation
    pass

## RULE: Pop-up Windows
## STATUS: NOT STARTED
def is_popupwindow(url):
    """Determines if the URL uses pop-up windows."""
    # Placeholder for actual implementation
    pass

## RULE: IFrame Redirection
## STATUS: NOT STARTED
def is_iframe(url):
    """Determines if the URL uses an iframe."""
    # Placeholder for actual implementation
    pass

########################################################################################
## DOMAIN BASED FEATURES ###############################################################

## RULE: Age of Domain
## STATUS: NOT STARTED
def is_age_of_domain(url):
    """Determines if the URL's domain age is suspicious."""
    # Placeholder for actual implementation
    pass

## RULE: DNS Record
## STATUS: NOT STARTED
def is_dns_record(url):
    """Determines if the URL has a DNS record."""
    # Placeholder for actual implementation
    pass

## RULE: Web Traffic
## STATUS: NOT STARTED
def is_web_traffic(url):
    """Determines if the URL has suspicious web traffic."""
    # Placeholder for actual implementation
    pass

## RULE: Page Rank
## STATUS: NOT STARTED
def is_page_rank(url):
    """Determines if the URL has a suspicious page rank."""
    # Placeholder for actual implementation
    pass

## RULE: Google Index
## STATUS: NOT STARTED
def is_google_index(url):
    """Determines if the URL is indexed by Google."""
    # Placeholder for actual implementation
    pass

## RULE: Number of Links Pointing to Page
## STATUS: NOT STARTED
def is_links_pointing_to_page(url):
    """Determines if the URL has a suspicious number of links pointing to the page."""
    # Placeholder for actual implementation
    pass

## RULE: Statistical Reports
## STATUS: NOT STARTED
def is_statistical_report(url):
    """Determines if the URL has a suspicious statistical report."""
    # Placeholder for actual implementation
    pass

########################################################################################

def check_if_valid(url):
    """Checks if the URL is valid."""
    try:
        parsed_url = urlparse(url)
        return all([parsed_url.scheme, parsed_url.netloc])
    except Exception:
        return False

if __name__ == "__main__":
    test_urls = [
        "http://125.98.3.123/fake.html",
        "http://0x58.0xCC.0xCA.0x62/2/paypal.ca/index.html",
        "http://example.com",
        "http://bit.ly/2xT",
        "http://example.com/this-is-a-very-long-url-that-should-be-considered-suspicious-because-it-is-over-54-characters-long",
        "http://short.url",
        "http://user:password@example.com",
        "https://legit-website.com",
        "ftp://admin:admin@phishing-site.com",
        "http://www.legitimate.com",
        "http://www.legitimate.com//http://www.phishing.com",
        "https://secure-site.com",
        "https://example.com//http://another-phishing.com",
        "http://normal-site.com/some/path",
        "http://www.paypal.com",
        "http://www.Confirme-paypal.com",
        "https://legitimate-site.com",
        "http://fake-paypal-secure.com",
        "http://secure-login.example.com",
        "http://www.hud.ac.uk/students/",
        "http://www.paypal.com",
        "http://secure.paypal.com",
        "http://subdomain.paypal.com",
        "http://www.fake.paypal.com",
        "http://example.co.uk",
        "http://www.subdomain.subdomain.com",
        "http://www.example.edu",
        "http://www.hud.ac.uk/students/",
        "http://a.b.example.com/",
        "https://www.example.com",
        "http://example.com:80",       # Expected: Legitimate (Standard HTTP port)
        "https://example.com:443",     # Expected: Legitimate (Standard HTTPS port)
        "http://example.com:8080",     # Expected: Phishing (Non-standard port)
        "ftp://example.com:21",
        "http://https-www-paypal-it-webapps-mpp-home.soft-hair.com/",
        "https://example.com/",
        "http://example.com/"
    ]
    
    for url in test_urls:
        if not check_if_valid(url):
            print(f"Invalid URL: {url}")
            continue
        print(f"Testing URL: {url}")
        print(f"Is having IP: {is_having_ip(url)}")
        print(f"Is URL long: {is_url_long(url)}")
        #print(f"Is domain registration length: {is_domain_registration_length(url)}")
        print(f"Is shortening service: {is_shortening_service(url)}")
        print(f"Is having '@' symbol: {is_having_at_symbol(url)}")
        print(f"Is double: {is_double(url)}")
        print(f"Is prefix suffix: {is_prefix_suffix(url)}")
        print(f"Is having sub domain: {is_having_sub_domain(url)}")
        print(f"Is HTTPS: {is_https(url)}")
        # print(f"Is favicon: {is_favicon(url)}")
        print(f"Is port: {is_port(url)}")
        print(f"Is HTTPS token: {is_https_token(url)}")
        print()