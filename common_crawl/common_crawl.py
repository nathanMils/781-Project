import os
import gzip
import requests

def download_wet_index_file(url, output_dir="./common_crawl/wat_paths"):
    os.makedirs(output_dir, exist_ok=True)
    local_file = os.path.join(output_dir, "wet_paths.gz")

    if not os.path.exists(local_file):
        print(f"Downloading {url}...")
        response = requests.get(url, stream=True)
        with open(local_file, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)
        print(f"Downloaded to {local_file}")
    else:
        print(f"File already exists: {local_file}")

    return local_file

def extract_gz_file(gz_file, output_dir="./common_crawl/wat_paths"):
    extracted_file = gz_file.replace('.gz', '')
    if not os.path.exists(extracted_file):
        print(f"Extracting {gz_file}...")
        with gzip.open(gz_file, 'rt', encoding='utf-8') as f_in:
            with open(extracted_file, 'w', encoding='utf-8') as f_out:
                f_out.write(f_in.read())
        print(f"Extracted to {extracted_file}")
    else:
        print(f"File already extracted: {extracted_file}")

    return extracted_file

def read_wet_index_file(extracted_file):
    print(f"Reading extracted file: {extracted_file}...")
    with open(extracted_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in lines[:10]:
            print(line.strip())
    print(f"Read {len(lines)} lines.")

def download_wet_file(url, output_dir="./common_crawl/wat_data"):
    os.makedirs(output_dir, exist_ok=True)
    local_file = os.path.join(output_dir, os.path.basename(url))

    if not os.path.exists(local_file):
        print(f"Downloading {url}...")
        response = requests.get(url, stream=True)
        with open(local_file, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)
        print(f"Downloaded to {local_file}")
    else:
        print(f"File already exists: {local_file}")

    return local_file

# Function to extract .gz WET file
def extract_gz_file(gz_file, output_dir="./common_crawl/wat_data"):
    extracted_file = gz_file.replace('.gz', '')
    if not os.path.exists(extracted_file):
        print(f"Extracting {gz_file}...")
        with gzip.open(gz_file, 'rt', encoding='utf-8') as f_in:
            with open(extracted_file, 'w', encoding='utf-8') as f_out:
                f_out.write(f_in.read())
        print(f"Extracted to {extracted_file}")
    else:
        print(f"File already extracted: {extracted_file}")

    return extracted_file

# Function to read and print the WET file content
def read_wet_file(extracted_file):
    print(f"Reading extracted WET file: {extracted_file}...")
    with open(extracted_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in lines[:10]:  # Print the first 10 lines for preview
            print(line.strip())
    print(f"Read {len(lines)} lines.")

# def main():
#     wet_index_url = "https://data.commoncrawl.org/crawl-data/CC-MAIN-2024-42/wat.paths.gz"
    
#     gz_file = download_wet_index_file(wet_index_url)

#     extracted_file = extract_gz_file(gz_file)

#     read_wet_index_file(extracted_file)

def main():
    # URL to the WET file (example URL)
    wet_file_url = "https://data.commoncrawl.org/crawl-data/CC-MAIN-2024-42/segments/1727944253146.59/wat/CC-MAIN-20241003094020-20241003124020-00118.warc.wat.gz"
    
    # Download the WET file
    gz_file = download_wet_file(wet_file_url)

    # Extract the downloaded gzipped file
    extracted_file = extract_gz_file(gz_file)

    # Read the extracted WET file
    read_wet_file(extracted_file)

if __name__ == "__main__":
    main()
