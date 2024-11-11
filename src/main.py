from util import set_seed, setup_logging, fetch_data, fetch_data_local

SEED = 21

def configure():
    setup_logging()
    set_seed(SEED)

def start_server():
    # Start the flask server
    pass

def main():
    print("Hello, COS 781 Project!")
    data = fetch_data_local()

if __name__ == "__main__":
    configure()
    main()