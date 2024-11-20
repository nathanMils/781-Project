from util import setup_logging, fetch_data, fetch_data_local, prepare
from flask_server import start_server
import os

# Load environment variables
from dotenv import load_dotenv

SEED = 21

def configure():
    setup_logging()

def main():
    load_dotenv(dotenv_path='./.env')
    prepare()
    model_choice = input("Select model type (1: Decision Tree, 2: XGBoost, 3: Logistic Regression): ")
    if model_choice == '1':
        MODEL_TYPE = "Decision_Tree"
    elif model_choice == '2':
        MODEL_TYPE = "XGBoost"
    elif model_choice == '3':
        MODEL_TYPE = "Logistic_Regression"
    else:
        raise ValueError("Invalid model type selected")
    
    model_version = input("Select model version (e.g., 1, 2, 3): ")
    if model_version.isdigit():
        MODEL_VERSION = model_version
    else:
        raise ValueError("Invalid model version selected")
    print("Starting Project")
    print(f"Model Type: {MODEL_TYPE}")
    print(f"Model Version: {MODEL_VERSION}")
    start_server(model_uri=f"models:/{MODEL_TYPE}/{MODEL_VERSION}",model_name=MODEL_TYPE)

if __name__ == "__main__":
    configure()
    main()