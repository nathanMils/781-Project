import joblib

import logging
import os

logger = logging.getLogger('util.model_joblib')

MODEL_DIR = "../../configs/models"

def save_model(model, model_name, version: int = 0):
    if version == 0:
        while os.path.exists(f"{MODEL_DIR}/{model_name}_{version}.pkl"):
            version += 1
    logger.info(f"Saving model to {MODEL_DIR}/{model_name}_{version}.pkl")
    joblib.dump(model, f"{MODEL_DIR}/{model_name}_{version}.pkl")

def load_model(model_name, version: int = 0):
    logger.info(f"Loading model from {MODEL_DIR}/{model_name}_{version}.pkl")
    return joblib.load(f"{MODEL_DIR}/{model_name}.pkl")