import requests
import gzip
import io

# Function to download the CDX file
def download_cdx_file(cdx_url):
    response = requests.get(cdx_url)
    if response.status_code == 200:
        return response.content
    else:
        print(f"Failed to download file from {cdx_url}, Status code: {response.status_code}")
        return None

# Function to process the CDX data and extract URLs
def process_cdx_data(cdx_data):
    urls = []
    with gzip.GzipFile(fileobj=io.BytesIO(cdx_data)) as cdx_file:
        for line in cdx_file:
            try:
                # Decode each line to a string and split by whitespace
                line_parts = line.decode('utf-8').strip().split(' ')
                
                # URLs are typically in the 3rd position
                if len(line_parts) > 2:
                    url = line_parts[2]
                    urls.append(url)
            except Exception as e:
                print(f"Error processing line: {e}")
    return urls

# Function to save the extracted URLs to CSV
import pandas as pd
def save_to_csv(urls, output_file='urls.csv'):
    df = pd.DataFrame(urls, columns=['URL'])
    df.to_csv(output_file, index=False)
    print(f"Saved {len(urls)} URLs to {output_file}")

# Example usage
cdx_url = 'https://data.commoncrawl.org/crawl-data/CC-MAIN-2024-42/segments/1699533706582/cdx/CC-MAIN-20241009182559-20241009212559-00000.cdx.gz'
cdx_data = download_cdx_file(cdx_url)

if cdx_data:
    urls = process_cdx_data(cdx_data)
    save_to_csv(urls)
