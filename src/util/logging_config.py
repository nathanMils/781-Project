import logging
import logging.config
import json
import argparse
import os

LOGGING_CONFIG_PATH = os.path.join(os.path.dirname(__file__), '../../configs/logging_config.json')

def setup_logging(config_path=LOGGING_CONFIG_PATH):
    """Sets up logging configuration using a JSON file."""
    with open(config_path, 'r') as config_file:
        config = json.load(config_file)
        logging.config.dictConfig(config)
