import pandas as pd
import os

from ucimlrepo import fetch_ucirepo
from scipy.io import arff

import logging

logger = logging.getLogger('util.data')

def fetch_data():
    logger.info("Fetching phishing websites dataset from UCI ML Repository")
    phishing_websites = fetch_ucirepo(id=327) 
    
    X = phishing_websites.data.features 
    y = phishing_websites.data.targets 

    return pd.concat([X, y], axis=1)

DATASET_PATH= "../../data/Training_Dataset.arff"

def fetch_data_local():
    logger.info("Fetching phishing websites dataset from local .arff file")
    arff_file_path = os.path.join(os.path.dirname(__file__), DATASET_PATH)
    data, _ = arff.loadarff(arff_file_path)
    
    df = pd.DataFrame(data)
    X = df.drop('Result', axis=1)
    y = df['Result']

    return pd.concat([X, y], axis=1)