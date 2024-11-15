from flask import Flask, request, jsonify
from flask_cors import CORS
import csv
import pandas as pd
from process import is_phishing_information_gain, is_phishing_composite, is_phishing

import pandas as pd

import mlflow.pyfunc
model = None
mlflow.set_tracking_uri("./mlruns")

dataset_type = None

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

def run_by_dataset_type(dataset_type, func, *args):
    if dataset_type == "IG":
        return func(is_phishing_information_gain, *args)
    elif dataset_type == "Comp":
        return func(is_phishing_composite, *args)
    else:
        raise ValueError("Invalid dataset type")

collected_data = []

CSV_FILE_PATH = 'collected_data.csv'


def initialize_csv():
    try:
        with open(CSV_FILE_PATH, mode='a', newline='') as file:
            writer = csv.writer(file)
            if file.tell() == 0:
                headers = [
                    "having_ip_address",
                    "url_length",
                    "shortining_service",
                    "having_at_symbol",
                    "double_slash_redirecting",
                    "prefix_suffix",
                    "having_sub_domain",
                    "sslfinal_state",
                    "domain_registration_length",
                    "favicon",
                    "port",
                    "https_token",
                    "request_url",
                    "url_of_anchor",
                    "links_in_tags",
                    "sfh",
                    "submitting_to_email",
                    "abnormal_url",
                    "redirect",
                    "on_mouseover",
                    "rightclick",
                    "popupwindow",
                    "iframe",
                    "age_of_domain",
                    "dnsrecord",
                    "web_traffic",
                    "page_rank",
                    "google_index",
                    "links_pointing_to_page",
                    "statistical_report"
                ]
                writer.writerow(headers)
    except Exception as e:
        logger.error(f"Error initializing CSV file: {str(e)}")

app = Flask(__name__)
CORS(app)

@app.route('/collect', methods=['POST'])
def collect():
    start_time = time.time()
    try:
        logger.info("Received Collect request")
        data = request.get_json()
        url = data.get('url')
        html = data.get('html')

        characteristics, preprocess_time = time_run_check(is_phishing, url, html)
        logger.info(f"Data: {characteristics}, Processing time: {preprocess_time}")

        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.info(f"Request processing time: {elapsed_time}")

        is_phishing_result = 1
        collected_data = characteristics

        if collected_data is None:
            return jsonify(
                {
                    "error": "Unable to collect data for URL"
                }
            ), 400
        
        with open(CSV_FILE_PATH, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(collected_data)

        return jsonify(
            {
                "message": "URL tested successfully!",
                "is_phishing": is_phishing_result,
            }
        ), 200
    except Exception as e:
        logger.error(f"Error: URL: {str(e)}")
        return jsonify(
            {
                "error": "Unable to predict URL"
            }
        ), 400

@app.route('/predict_url', methods=['POST'])
def predict():
    start_time = time.time()
    try:
        logger.info("Received request to test URL")
        data = request.get_json()
        url = data.get('url')
        logger.info(f"URL: {url}")

        characteristics, preprocess_time = time_run_check(is_phishing, url)
        logger.info(f"Data: {characteristics}, Processing time: {preprocess_time}")

        df = pd.DataFrame([characteristics])

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
        characteristics, preprocess_time = run_by_dataset_type(dataset_type, time_run_check, url, html)
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

def start_server(model_uri, dataset):
    global model, dataset_type
    model = mlflow.pyfunc.load_model(model_uri)
    dataset_type = dataset
    logger.info("Starting Flask server")
    initialize_csv()
    app.run(debug=True, port=5000)

# To start the server, you would call:
# start_server('runs:/<run_id>/model') where <run_id> is your MLflow run ID
