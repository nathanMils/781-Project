import asyncio
import httpx
import pandas as pd
from tqdm import tqdm
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def configure_driver():
    chrome_options = Options()
    chrome_options.headless = True
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--no-sandbox')

    driver_path = '/home/nathan/chromedriver-linux64/chromedriver'
    service = Service(driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver

async def post_to_flask_api(client, url, page_source):
    try:
        print(f"Posting data for URL: {url}")
        # Asynchronously post data to Flask API
        response = await client.post(
            'http://127.0.0.1:5000/collect',
            json={'url': url, 'html': page_source}
        )
        if response.status_code != 200:
            print(f"Error in posting data for URL: {url}")
        return response.status_code
    except Exception as e:
        print(f"Exception in posting to Flask API: {e}")
        return None

def collect_website_info(driver, url):
    try:
        driver.get(url)

        # Wait for an anchor tag (you can adjust the condition based on your needs)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'a')))

        page_title = driver.title
        page_source = driver.page_source
        return {
            'url': url,
            'title': page_title,
            'html': page_source
        }
    except Exception as e:
        print(f"Error accessing {url}: {e}")
        return None

async def process_urls(driver, urls):
    collected_data = []
    async with httpx.AsyncClient() as client:
        tasks = []
        for url in urls:
            info = collect_website_info(driver, url)
            if info:
                collected_data.append(info)
                # Asynchronously post to Flask API
                tasks.append(post_to_flask_api(client, info['url'], info['html']))

        # Wait for all the post requests to complete
        await asyncio.gather(*tasks)

    return collected_data

def main():
    driver = configure_driver()
    df = pd.read_csv('./data/phishtank/verified_online.csv')
    urls = df['url'].iloc[2000:10000].tolist()

    # Run the async process to collect and post data
    loop = asyncio.get_event_loop()
    collected_data = loop.run_until_complete(process_urls(driver, urls))

    # Save the collected data to CSV if any data is collected
    if collected_data:
        collected_df = pd.DataFrame(collected_data)
        collected_df.to_csv('collected_website_info.csv', index=False)

    driver.quit()

if __name__ == "__main__":
    main()
