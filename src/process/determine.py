from urllib.parse import urlparse
import re
import whois
from datetime import datetime

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
## STATUS: NOT STARTED
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
## STATUS: NOT STARTED
def is_having_at_symbol(url):
    """Determines if the URL contains an '@' symbol."""
    # Placeholder for actual implementation
    pass

## RULE: Redirecting using "//"
## STATUS: NOT STARTED
def is_double(url):
    """Determines if the URL redirects using '//'."""
    # Placeholder for actual implementation
    pass

## RULE: Adding Prefix or Suffix Separated by (-) to the Domain
## STATUS: NOT STARTED
def is_prefix_suffix(url):
    """Determines if the URL has a prefix or suffix separated by a hyphen."""
    # Placeholder for actual implementation
    pass

## RULE: Sub Domain and Multi Sub Domains
## STATUS: NOT STARTED
def is_having_sub_domain(url):
    """Determines if the URL has multiple subdomains."""
    # Placeholder for actual implementation
    pass

## RULE: HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer)
## STATUS: NOT STARTED
def is_https(url):
    """Determines if the URL uses HTTPS."""
    # Placeholder for actual implementation
    pass


TODAY = datetime.now()

## RULE: Domain Registration Length
## STATUS: NOT STARTED
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
## STATUS: NOT STARTED
def is_favicon(url):
    """Determines if the URL has a favicon."""
    # Placeholder for actual implementation
    pass

## RULE: Using Non-Standard Port
## STATUS: NOT STARTED
def is_port(url):
    """Determines if the URL uses a non-standard port."""
    # Placeholder for actual implementation
    pass

## RULE: HTTP and HTTPS Tokens
## STATUS: NOT STARTED
def is_https_token(url):
    """Determines if the URL has 'https' tokens."""
    # Placeholder for actual implementation
    pass

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

if __name__ == "__main__":
    test_urls = [
        "http://125.98.3.123/fake.html",
        "http://0x58.0xCC.0xCA.0x62/2/paypal.ca/index.html",
        "http://example.com",
        "http://bit.ly/2xT",
        "http://example.com/this-is-a-very-long-url-that-should-be-considered-suspicious-because-it-is-over-54-characters-long",
        "http://short.url"
    ]
    
    for url in test_urls:
        print(f"Testing URL: {url}")
        print(f"Is having IP: {is_having_ip(url)}")
        print(f"Is URL long: {is_url_long(url)}")
        #print(f"Is domain registration length: {is_domain_registration_length(url)}")
        print(f"Is shortening service: {is_shortening_service(url)}")
        print()