from flask import Flask, request, jsonify
from flask_cors import CORS
import signal
import pandas as pd
from process import is_phishing_no_html, is_phishing

import mlflow.pyfunc
model = None
mlflow.set_tracking_uri("./mlruns")

import logging

logger = logging.getLogger('flask_server.server')

import time
import json
import os

def time_run_check(func, *args):
    start_time = time.time()
    result = func(*args)
    elapsed_time = time.time() - start_time
    return result, elapsed_time

collected_data = []

# Intercept SIGINT signal and save collected data before shutting down
def shutdown_handler(_signum, _frame):
    logger.info("Server is stopping... saving collected data.")
    with open('collected_data.json', 'w') as f:
        json.dump(collected_data, f, default=str)

# Register signal handler for graceful shutdown on Ctrl+C
signal.signal(signal.SIGINT, shutdown_handler)

app = Flask(__name__)
CORS(app)

@app.route('/predict_url', methods=['POST'])
def predict():
    start_time = time.time()
    try:
        # Retrieve the URL from the request
        logger.info("Received request to test URL")
        data = request.get_json()
        url = data.get('url')
        logger.info(f"URL: {url}")

        # Process URL and determine characteristics
        characteristics, preprocess_time = time_run_check(is_phishing_no_html, url)
        logger.info(f"Data: {characteristics}, Processing time: {preprocess_time}")

        # Convert the characteristics to a DataFrame
        df = pd.DataFrame([characteristics])

        # Predict the URL using the loaded model
        prediction, predict_time = time_run_check(model.predict, df)

        logger.info(f"Prediction: {prediction[0]}, Prediction time: {predict_time}")

        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.info(f"Request processing time: {elapsed_time}")

        collected_data.append({
            "url": url,
            "data": characteristics,
            "prediction": prediction[0],
            "processing_time": elapsed_time,
            "preprocess_time": preprocess_time,
            "prediction_time": predict_time
        })

        return jsonify(
            {
                "message": "URL tested successfully!",
                "is_phishing": not bool(prediction[0]),
                "processing_time": elapsed_time,
                "preprocess_time": preprocess_time,
                "prediction_time": predict_time

            }
        ), 200
    except Exception as e:
        logger.error(f"Error: URL: {str(e)}")
        return jsonify(
            {
                "error": "Unable to predict URL"
            }
        ), 400
    
@app.route('/predict_url_html', methods=['POST'])
def predict_html():
    start_time = time.time()
    try:
        # Retrieve the URL and HTML from the request
        logger.info("Received request to test URL")
        data = request.get_json()
        url = data.get('url')
        html = data.get('html')
        logger.info(f"URL: {url}")

        # Process URL and determine characteristics
        characteristics, preprocess_time = time_run_check(is_phishing, url, html)
        logger.info(f"Data: {characteristics}, Processing time: {preprocess_time}")

        # Convert the characteristics to a DataFrame
        df = pd.DataFrame([characteristics])

        # Predict the URL and HTML using the loaded model
        prediction, predict_time = time_run_check(model.predict, df)

        logger.info(f"Prediction: {prediction[0]}, Prediction time: {predict_time}")

        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.info(f"Request processing time: {elapsed_time}")

        collected_data.append({
            "url": url,
            "data": characteristics,
            "prediction": prediction[0],
            "processing_time": elapsed_time,
            "preprocess_time": preprocess_time,
            "prediction_time": predict_time
        })

        return jsonify(
            {
                "message": "URL tested successfully!",
                "is_phishing": not bool(prediction[0]),
                "processing_time": elapsed_time,
                "preprocess_time": preprocess_time,
                "prediction_time": predict_time
            }
        ), 200
    except Exception as e:
        logger.error(f"Error: URL: {str(e)}")
        return jsonify(
            {
                "error": "Unable to predict URL"
            }
        ), 400

def start_server(model_uri):
    global model
    model = mlflow.pyfunc.load_model(model_uri)
    logger.info("Starting Flask server")
    app.run(debug=True, port=5000)

# To start the server, you would call:
# start_server('runs:/<run_id>/model') where <run_id> is your MLflow run ID
