from util import setup_logging, fetch_data, fetch_data_local
from flask_server import start_server
import os

# Load environment variables
from dotenv import load_dotenv

SEED = 21

def configure():
    setup_logging()

def main():
    load_dotenv(dotenv_path='./.env')
    MODEL_TYPE = os.getenv("MODEL_TYPE")
    MODEL_VERSION = os.getenv("MODEL_VERSION")
    DATASET = os.getenv("DATASET")
    print("Starting Project")
    print(f"Model Type: {MODEL_TYPE}")
    print(f"Model Version: {MODEL_VERSION}")
    print(f"Dataset: {DATASET}")
    start_server(model_uri=f"models:/{MODEL_TYPE}_{DATASET}/{MODEL_VERSION}", dataset=DATASET)

if __name__ == "__main__":
    configure()
    main()