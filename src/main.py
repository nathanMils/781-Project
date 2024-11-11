from util import set_seed, setup_logging, fetch_data, fetch_data_local
from flask_server import start_server

SEED = 21

def configure():
    setup_logging()
    set_seed(SEED)

def main():
    print("Hello, COS 781 Project!")
    start_server()

if __name__ == "__main__":
    configure()
    main()