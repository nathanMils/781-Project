from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
from process import is_phishing_no_html, is_phishing

import mlflow.pyfunc
model = None
mlflow.set_tracking_uri("./mlruns")

import logging

logger = logging.getLogger('flask_server.server')

app = Flask(__name__)
CORS(app)

@app.route('/predict_url', methods=['POST'])
def predict():
    try:
        # Retrieve the URL from the request
        logger.info("Received request to test URL")
        data = request.get_json()
        url = data.get('url')
        logger.info(f"URL: {url}")

        # Process URL and determine characteristics
        characteristics = is_phishing_no_html(url)
        logger.info(f"Data: {characteristics}")

        # Convert the characteristics to a DataFrame
        df = pd.DataFrame([characteristics])

        # Predict the URL using the loaded model
        prediction = model.predict(df)

        logger.info(f"Prediction: {prediction[0]}")

        return jsonify(
            {
                "message": "URL tested successfully!",
                "is_phishing": not bool(prediction[0])
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
    try:
        # Retrieve the URL and HTML from the request
        logger.info("Received request to test URL")
        data = request.get_json()
        url = data.get('url')
        html = data.get('html')
        logger.info(f"URL: {url}")

        # Process URL and determine characteristics
        characteristics = is_phishing(url, html)
        logger.info(f"Data: {characteristics}")

        # Convert the characteristics to a DataFrame
        df = pd.DataFrame([characteristics])

        # Predict the URL and HTML using the loaded model
        prediction = model.predict(df)

        return jsonify(
            {
                "message": "URL tested successfully!",
                "is_phishing": not bool(prediction[0])
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
