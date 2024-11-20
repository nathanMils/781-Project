import pandas as pd
import random

# Load the CSV files
csv1 = pd.read_csv('common_crawl/extracted_urls.csv')
csv2 = pd.read_csv('data/test_final/open_phish_unseen.csv')

sample1 = csv1.sample(n=50, random_state=1)
sample2 = csv2.sample(n=50, random_state=1)

sample1['result'] = 1
sample2['result'] = -1

combined = pd.concat([sample1, sample2])

combined = combined.sample(frac=1, random_state=1).reset_index(drop=True)
combined.to_csv('data/test_final/live_test.csv', index=False)