import requests
import json

# Function to check if a URL is a known phishing URL
# PhishTank API documentation: https://www.phishtank.com/developer_info.php
# PhishTank does not allow new user registration so rate limits are very low
def check_url(url, app_key=None):
    api_url = 'http://checkurl.phishtank.com/checkurl/'
    params = {
        'url': url,
        'format': "json"
    }
    if app_key:
        params['app_key'] = app_key

    response = requests.post(api_url, data=params)
    
    if response.status_code == 200:
        return response.json()
    else:
        return f"Error: {response.status_code}"

if __name__ == '__main__':
    url = 'http://www.google.com'
    result = check_url(url)
    print(json.dumps(result, indent=4))