import json  # Using JSON instead of pickle
from flask import Flask, request, jsonify
import logging
import os
from urllib.parse import urlparse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import html # For escaping
# from flask_wtf.csrf import CSRFProtect # Import for CSRF protection

app = Flask(__name__)
CORS(app, resources={r"/data": {"origins": ["https://example.com", "https://www.example.com"]}})  # Configure CORS
# csrf = CSRFProtect(app) # Enable CSRF protection

# Configure logging (important for production)
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configure Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Set Secret Key
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_default_secret_key') # Replace with a strong, random key

# Securely handle data using JSON instead of pickle
@app.route('/data', methods=['POST'])
@limiter.limit("10 per minute")  # Apply rate limiting to this endpoint
def data_handler():
    """
    Receives data as JSON, processes it, and returns a response.
    """
    if request.headers.get('Content-Type') != 'application/json':
        return jsonify({"error": "Invalid Content-Type, must be application/json"}), 400

    try:
        data = request.get_json()  # Get JSON data from the request
        if not data:
            return jsonify({"error": "No data received"}), 400

        # Process the data (example: log it)
        logging.info(f"Received data: {data}")

        # Perform operations on the data (safely)
        # Example: Accessing a specific field
        if 'name' in data:
            name = data['name']
            escaped_name = html.escape(name)
            return jsonify(f"Hello, {escaped_name}!"), 200
        else:
            return jsonify({"error": "Name not provided in the data"}), 400

    except Exception as e:
        logging.error(f"Error processing data: {e}")
        return jsonify({"error": "Error processing data"}), 500


# Example of handling URLs (demonstrates parsing, not directly related to the original pickle issue)
@app.route('/url', methods=['GET'])
@limiter.limit("5 per minute")  # Apply rate limiting to this endpoint
def url_handler():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        parsed_url = urlparse(url)
        logging.info(f"Parsed URL: {parsed_url}")

        # Example: Check the hostname (be careful with this in real-world scenarios)
        # Hostname validation is easily bypassed.  Consider alternatives like API keys.
        allowed_hostnames = ["example.com", "www.example.com"]  # Use an allowlist
        if parsed_url.hostname in allowed_hostnames:
            return jsonify("URL is from an allowed domain"), 200
        else:
            return jsonify("URL is not from an allowed domain"), 403

    except Exception as e:
        logging.error(f"Error parsing URL: {e}")
        return jsonify({"error": "Invalid URL"}), 400


# Example of setting security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    #  Consider a more restrictive Content-Security-Policy for production
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';"
    return response


if __name__ == '__main__':
    #  Never run with debug=True in production!
    #  This is a security risk.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

