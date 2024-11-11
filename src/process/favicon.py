import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

def get_favicon_domain(url):
    try:
        # Forcing requests to ignore SSL verification for this test
        response = requests.get(url, verify=False)
        if response.status_code != 200:
            return None
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        favicon_url = None
        for link in soup.find_all('link', rel='icon'):
            favicon_url = link.get('href')
            if favicon_url:
                break

        if not favicon_url:
            return None
        
        favicon_url = urljoin(url, favicon_url)
        favicon_domain = urlparse(favicon_url).netloc
        page_domain = urlparse(url).netloc
        
        return favicon_domain, page_domain
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching favicon from {url}: {e}")
        return None, None
