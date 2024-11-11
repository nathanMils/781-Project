import pandas as pd
import os

from ucimlrepo import fetch_ucirepo
from scipy.io import arff

def fetch_data():
    phishing_websites = fetch_ucirepo(id=327) 
    
    X = phishing_websites.data.features 
    y = phishing_websites.data.targets 

    return pd.concat([X, y], axis=1)

DATASET_PATH= ".../data/phishing_websites.arff"

def fetch_data_local():
    arff_file_path = os.path.join(os.path.dirname(__file__), DATASET_PATH)
    data, _ = arff.loadarff(arff_file_path)
    
    df = pd.DataFrame(data)
    X = df.drop('Result', axis=1)
    y = df['Result']

    return pd.concat([X, y], axis=1)