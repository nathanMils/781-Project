import json
import pandas as pd

def read_json_to_dict(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data


file_path = './data/collected/time_data.json'
data_dict = read_json_to_dict(file_path)

time_data = []

for value in data_dict:
    time_data.append(value['Timing Data'])

df = pd.DataFrame(time_data)
average_values = df.mean()

times = pd.DataFrame(list(average_values.items()), columns=['feature', 'time'])
min_weight, max_weight = 0.1, 1.0

times['normalized_weight'] = 1- (((times['time'] - times['time'].min()) / (times['time'].max() - times['time'].min())) * (max_weight - min_weight) + min_weight)

feature_weights = dict(zip(times['feature'], times['normalized_weight']))

with open('./data/collected/time_weights.json', 'w') as f:
        json.dump(feature_weights, f, indent=4)