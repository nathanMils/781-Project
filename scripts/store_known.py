import requests

def download_csv(url, save_path):
    response = requests.get(url)
    if response.status_code == 200:
        with open(save_path, 'wb') as file:
            file.write(response.content)
        print(f"File downloaded and saved to {save_path}")
    else:
        print(f"Failed to download file. Status code: {response.status_code}")

if __name__ == "__main__":
    url = "https://data.phishtank.com/data/online-valid.csv"
    save_path = "./data/phishtank/known_online_valid.csv"
    download_csv(url, save_path)