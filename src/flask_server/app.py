from flask import Flask, request, jsonify
from flask_cors import CORS

import logging

logger = logging.getLogger('flask_server.server')

app = Flask(__name__)
CORS(app)

@app.route('/receive_url', methods=['POST'])
def receive_url():
    try:
        logger.info("Received request to receive URL")
        data = request.get_json()
        
        url = data.get('url')
        
        logger.info(f"Received URL: {url}")

        return jsonify({"message": "URL received successfully!"}), 200
    
    except Exception as e:
        logger.error(f"Error receiving URL: {str(e)}")
        return jsonify({"error": str(e)}), 400
    
def start_server():
    logger.info("Starting Flask server")
    app.run(debug=True, port=5000)