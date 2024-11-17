from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import time
import pandas as pd
from tqdm import tqdm
import requests
import random

def main():
    chrome_options = Options()
    chrome_options.headless = True
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--no-sandbox')
    
    # extension_path = '/home/nathan/Desktop/781-Project/local-chrome-extension'
    # chrome_options.add_argument(f'--load-extension={extension_path}')

    driver_path = '/home/nathan/chromedriver-linux64/chromedriver'

    # chrome_options.binary_location = "/usr/bin/google-chrome"

    service = Service(driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)

    def collect_website_info(url):
        try:
            driver.get(url)

            # Wait for the page to load or timeout after 10 seconds
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'a')))

            page_title = driver.title
            page_source = driver.page_source

            # Send collected data to the Flask API
            print("send")
            response = requests.post('http://127.0.0.1:5000/collect', json={'url': url, 'html': page_source})
            if response.status_code != 200:
                print(f"Error in collecting data for URL: {url}")

            return {
                'url': url,
                'title': page_title,
                'html': page_source
            }

        except TimeoutException:
            return None

        except Exception as e:
            # Handle other exceptions
            print(f"An error occurred: {e}")
            return None

    df = pd.read_csv('./common_crawl/extracted_urls.csv')
    urls = df['url'].tolist()
    # Extract a random sample of 2500 URLs
    urls = random.sample(urls, min(len(urls), 2500))

    collected_data = []

    for url in tqdm(urls, desc="Processing URLs", ncols=100):
        info = collect_website_info(url)
        if info:
            collected_data.append(info)

    if collected_data:
        collected_df = pd.DataFrame(collected_data)
        collected_df.to_csv('collected_website_info.csv', index=False)

    driver.quit()

if __name__ == "__main__":
    main()
