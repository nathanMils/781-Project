import threading
import pandas as pd
import queue
import time
import random
import json
import os
from datetime import datetime
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import selenium
import logging
import coloredlogs
import uuid
from dotenv import load_dotenv

from scraper.rules import collect_data

# Parallelism
data_queue = queue.Queue()

def setup_logging():
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    coloredlogs.install(level='INFO', fmt=log_format)

def get_chromedriver_path():
    chromedriver_path = os.getenv('CHROMEDRIVER_PATH')
    if chromedriver_path is None:
        raise ValueError("Environment variable 'CHROMEDRIVER_PATH' is not set.")
    return chromedriver_path

def is_url_reachable(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            logging.info(f"URL reachable: {url}")
            return True
        else:
            logging.warning(f"URL not reachable: {url} (Status code: {response.status_code})")
            return False
    except requests.RequestException as e:
        logging.error(f"Error reaching URL {url}: {e}")
        return False

def setup_driver():
    options = Options()
    chrome_options = Options()
    chrome_options.headless = True
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--no-sandbox')
    driver = webdriver.Chrome(service=Service(get_chromedriver_path()), options=options)
    return driver

def fetch_headers(driver):
    try:
        return driver.execute_script("return window.performance.getEntries()")
    except Exception:
        logging.error("Error fetching headers")
        return None

def scraper(csv_path, start, end, randomize=False):
    chrome_options = Options()
    chrome_options.headless = True
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--no-sandbox')
    
    def initialize_driver():
        try:
            return webdriver.Chrome(service=Service(get_chromedriver_path()), options=chrome_options)
        except Exception as e:
            logging.error(f"Failed to initialize the WebDriver: {e}")
            raise e

    driver = initialize_driver()
    urls = None
    if randomize:
        urls = pd.read_csv(csv_path)['url'].sample(n=end).tolist()
    else:
        urls = pd.read_csv(csv_path)['url'][start:end].tolist()

    for url in urls:
        logging.info(f"Checking if URL {url} is reachable...")
        if not is_url_reachable(url):
            logging.info(f"Skipping URL {url} because it is not reachable.")
            continue

        logging.info(f"Scraping {url}...")

        try:
            driver.get(url)
            WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
            logging.info(f"Page loaded: {url}")
        except selenium.common.exceptions.InvalidSessionIdException as e:
            logging.error(f"Invalid session for {url}: {e}")
            # Reinitialize the driver to recover from session loss
            driver.quit()
            driver = initialize_driver()
            continue
        except Exception as e:
            logging.error(f"Error loading page {url}: {e}")
            continue

        try:
            html_content = driver.page_source
            cookies = driver.get_cookies()
            headers = fetch_headers(driver)
            data_queue.put({'url': url, 'html': html_content, 'cookies': cookies, 'headers': headers})
            logging.info(f"Waiting for the parser to process {url}...")
            data_queue.join()
            time.sleep(random.uniform(3, 5))
        except Exception as e:
            logging.error(f"Error during data extraction for {url}: {e}", exc_info=True)
            
            continue

    driver.quit()

def parser():
    while True:
        task = data_queue.get()

        if task is None:
            break

        url = task['url']
        html_content = task['html']
        cookies = task['cookies']
        headers = task['headers']
        
        logging.info(f"Parsing data from {url}...")
        parse_data(url, html_content, cookies, headers)
        
        data_queue.task_done()


def parse_data(url, html_content, cookies, headers):
    try:
        open_rank, data = collect_data(url, html_content)
        if data is not None:
            append_html_to_json(url, html_content, cookies, headers, open_rank, data)
    except Exception as e:
        logging.error(f"Error parsing data for URL {url}: {e}")
        return "ERROR"

output_file = 'complete_data.json'

def generate_unique_id():
    return str(uuid.uuid4())

def append_html_to_json(url, html_content, cookies, headers, open_rank, data):
    data = {
        'id': generate_unique_id(),
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'html': html_content,
        'cookies': cookies,
        'headers': headers,
        'open_rank': open_rank,
        'data': data
    }

    if os.path.exists(output_file):
        with open(output_file, 'r+', encoding='utf-8') as file:
            try:
                existing_data = json.load(file)
                if not isinstance(existing_data, list):
                    existing_data = []
            except json.JSONDecodeError:
                existing_data = []
            existing_data.append(data)

            file.seek(0)
            json.dump(existing_data, file, indent=4)
    else:
        with open(output_file, 'w', encoding='utf-8') as file:
            json.dump([data], file, indent=4)

    logging.info(f"Appended HTML content for {url} in {output_file}")

def main():
    load_dotenv(dotenv_path='./.env')
    setup_logging()
    scraper_thread = threading.Thread(target=scraper, args=('common_crawl/extracted_urls.csv', 0, 2200, True))
    parser_thread = threading.Thread(target=parser)
    scraper_thread.start()
    parser_thread.start()
    scraper_thread.join()
    data_queue.put(None)
    parser_thread.join()

    logging.info("Scraping and parsing complete.")

if __name__ == "__main__":
    main()