from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import pandas as pd

def main():
    chrome_options = Options()
    chrome_options.headless = False  # Run in headless mode
    
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--no-sandbox')  # Often needed in Docker or VMs
    
    # Load your extension if necessary
    extension_path = '/home/nathan/Desktop/781-Project/local-chrome-extension'
    chrome_options.add_argument(f'--load-extension={extension_path}')

    # Path to ChromeDriver
    driver_path = '/home/nathan/Desktop/chromedriver-linux64/chromedriver'

    chrome_options.binary_location = "/usr/bin/google-chrome"

    # Initialize the WebDriver service
    service = Service(driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)

    def collect_website_info(url):
        try:
            driver.get(url)

            # Use WebDriverWait to wait for the page to load (for better accuracy than sleep)
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'a')))

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
            print(f"Error fetching data for {url}: {e}")
            return None

    df = pd.read_csv('./data/phishtank/verified_online.csv')
    urls = df['url'].head(2000).tolist()

    collected_data = []

    for url in urls:
        print(f"Processing: {url}")
        info = collect_website_info(url)
        if info:
            collected_data.append(info)

    # Convert collected data into DataFrame for further processing (optional)
    if collected_data:
        collected_df = pd.DataFrame(collected_data)
        collected_df.to_csv('collected_website_info.csv', index=False)

    driver.quit()  # Make sure to quit the driver at the end

if __name__ == "__main__":
    main()
