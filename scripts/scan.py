from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import time
import pandas as pd

def main():
    chrome_options = Options()
    chrome_options.headless = True
    
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')

    extension_path = '/home/nathan/Desktop/781-Project/local-chrome-extension'
    chrome_options.add_argument(f'--load-extension={extension_path}')

    driver_path = '/home/nathan/Desktop/chromedriver-linux64/chromedriver'

    service = Service(driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    def collect_website_info(url):
        try:
            driver.get(url)
            time.sleep(2)
            page_title = driver.title
            page_source = driver.page_source
            links = [a.get_attribute('href') for a in driver.find_elements(By.TAG_NAME, 'a')]
            print("Title:", page_title)
            print("Number of links:", len(links))
            print("Source length:", len(page_source))

            return {
                "title": page_title,
                "links": links,
                "source": page_source
            }

        except Exception as e:
            print("Error:", e)
            return None

    
    df = pd.read_csv('./data/phishtank/verified_online.csv')

    urls = df['url'].head(1000).tolist()

    for url in urls:
        info = collect_website_info(url)

    driver.quit()


if __name__ == "__main__":
    main()