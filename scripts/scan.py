from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import pandas as pd
from tqdm import tqdm
import requests

def main():
    chrome_options = Options()
    chrome_options.headless = True
    
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--no-sandbox')
    
    driver_path = '/home/nathan/Desktop/chromedriver-linux64/chromedriver'

    chrome_options.binary_location = "/usr/bin/google-chrome"

    service = Service(driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)

    def is_url_online(url):
        """
        Checks if the URL is reachable and returns True if the status is 200 OK.
        """
        try:
            # Use 'requests.head' to only check the status of the URL without downloading the entire content
            response = requests.head(url, allow_redirects=True, timeout=1)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def collect_website_info(url):
        try:
            # Use Selenium to get the URL and process the page
            driver.get(url)
            WebDriverWait(driver, 4).until(EC.presence_of_element_located((By.TAG_NAME, 'div')))

            # Check if the redirected URL is valid
            if not is_url_online(url):
                print(f"Skipping {url} as it's no longer reachable.")
                return None

            page_title = driver.title
            page_source = driver.page_source

            response = requests.post('http://127.0.0.1:5000/collect', json={'url': url, 'html': page_source})
            if response.status_code != 200:
                print(f"Error in collecting data for URL: {url}")

            return {
                'url': url,
                'title': page_title,
                'html': page_source
            }

        except Exception as e:
            print(f"Error processing {url}: {e}")
            return None

    # Load the list of URLs
    df = pd.read_csv('./data/phishtank/verified_online.csv')
    urls = df['url'].iloc[550:10000].tolist()

    collected_data = []

    # Iterate over the URLs and collect information
    for url in tqdm(urls, desc="Processing URLs", ncols=100):
        info = collect_website_info(url)
        if info:
            collected_data.append(info)

    # Save collected data to a CSV file
    if collected_data:
        collected_df = pd.DataFrame(collected_data)
        collected_df.to_csv('collected_website_info.csv', index=False)

    # Close the Selenium WebDriver
    driver.quit()

if __name__ == "__main__":
    main()
