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

            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'div')))

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

            return None

    df = pd.read_csv('./data/phishtank/verified_online_2.csv')
    urls = df['url'].iloc[5000:10000].tolist()

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
