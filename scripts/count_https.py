import pandas as pd 

df = pd.read_csv('./data/phishtank/known_online_valid.csv')

https_count = df['url'].str.contains('https:').sum()
http_count = df['url'].str.contains('http:').sum()

total = df['url'].count()

print(f'HTTPS URLs: {https_count}')
print(f'HTTP URLs: {http_count}')
print(f'Total URLs: {total}')

perc_https = (https_count / total) * 100
perc_http = (http_count / total) * 100

print(f'Percentage of HTTPS URLs: {perc_https:.2f}%')
print(f'Percentage of HTTP URLs: {perc_http:.2f}%')