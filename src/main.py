from util import set_seed, setup_logging, fetch_data, fetch_data_local
from flask_server import start_server
import os

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

SEED = 21
RUN_ID = os.getenv("MODEL_ID")

def configure():
    setup_logging()
    set_seed(SEED)

def main():
    print("Starting Project")
    start_server(model_uri=f"runs:/{RUN_ID}/model")

if __name__ == "__main__":
    configure()
    main()