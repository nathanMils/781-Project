from flask import Flask, request, jsonify
from flask_cors import CORS
import csv
import pandas as pd
from process import calculate, calculate_LGR
import numpy as np

import pandas as pd

import mlflow.pyfunc
model = None
mlflow.set_tracking_uri("./mlruns")

model_type = None

import logging

logger = logging.getLogger(__name__)

import time
import json
import os

def time_run_check(func, *args):
    start_time = time.time()
    result = func(*args)
    elapsed_time = time.time() - start_time
    return result, elapsed_time

collected_data = []

CSV_FILE_PATH = 'collected_data.csv'

def calculate_by_model_type(url, html=None):
    if model_type == "Logistic_Regression":
        return calculate_LGR(url, html)
    else:
        return calculate(url, html)


def write_to_csv(collected_data):
    try:
        # Open the CSV file and append new data
        with open(CSV_FILE_PATH, mode='a', newline='') as file:
            writer = csv.writer(file)

            # If the file is empty, write headers
            if file.tell() == 0:
                headers = [
                    "url",
                    "data",
                    "prediction",
                    "processing_time",
                    "preprocess_time",
                    "prediction_time"
                ]
                writer.writerow(headers)

            writer.writerow(collected_data.values())

    except Exception as e:
        logger.error(f"Error writing to CSV: {str(e)}")

app = Flask(__name__)
CORS(app)

@app.route('/predict_url', methods=['POST'])
def predict():
    start_time = time.time()
    try:
        logger.info("Received request to test URL")
        data = request.get_json()
        url = data.get('url')
        html = data.get('html')
        logger.info(f"URL: {url}")

        characteristics, preprocess_time = time_run_check(calculate_by_model_type, url, html)
        logger.info(f"Data: {characteristics}, Processing time: {preprocess_time}")

        if characteristics is None:
            return jsonify(
                {
                    "error": "Unable to process URL"
                }
            ), 400

        df = pd.DataFrame([characteristics])

        prediction, predict_time = time_run_check(model.predict, df)

        logger.info(f"Prediction: {prediction[0]}, Prediction time: {predict_time}")

        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.info(f"Request processing time: {elapsed_time}")

        predicted = prediction[0]
        logger.info(f"Predicted: {predicted}")
        def convert_to_int(obj):
            if isinstance(obj, (np.int64, np.float64)):  # Check if the value is a numpy int64 or float64
                return int(obj)  # Convert to native Python int
            elif isinstance(obj, dict):
                return {k: convert_to_int(v) for k, v in obj.items()}  # Recursively apply for dict
            elif isinstance(obj, list):
                return [convert_to_int(v) for v in obj]  # Recursively apply for list
            else:
                return obj
            
        data_to_return = {
            "message": "URL tested successfully!",
            "is_phishing": predicted,
            "processing_time": elapsed_time,
            "preprocess_time": preprocess_time,
            "prediction_time": predict_time
        }
        data_to_return = convert_to_int(data_to_return)

        return jsonify(data_to_return), 200
    except Exception as e:
        logger.error(f"Error: URL: {str(e)}")
        logger.error("Exception occurred")
        return jsonify(
            {
                "error": "Unable to predict URL"
            }
        ), 400

def start_server(model_uri, model_name):
    global model, model_type
    model_type = model_name
    model = mlflow.pyfunc.load_model(model_uri)
    logger.info("Starting Flask server")
    app.run(debug=False, port=5000)

# To start the server, you would call:
# start_server('runs:/<run_id>/model') where <run_id> is your MLflow run ID
