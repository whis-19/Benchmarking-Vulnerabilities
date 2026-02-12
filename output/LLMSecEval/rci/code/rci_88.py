import json
from flask import Flask, request, jsonify, make_response
import secrets
import os
import logging
import re  # For input validation
from flask_wtf import CSRFProtect  # For CSRF protection
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_cors import CORS


app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='error.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Securely manage the secret key
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    logging.critical("FLASK_SECRET_KEY environment variable not set.  Exiting.")
    raise ValueError("FLASK_SECRET_KEY environment variable not set.")
app.config['SECRET_KEY'] = SECRET_KEY

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,  # Use IP address for rate limiting
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# Enforce HTTPS and set security headers
talisman = Talisman(app, force_https=True, content_security_policy={
    'default-src': ['\'self\''],
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Example: Allow scripts from CDN
    'style-src': ['\'self\'', 'https://fonts.googleapis.com'],  # Example: Allow styles from Google Fonts
    'img-src': ['\'self\'', 'data:']  # Example: Allow images from data URIs
})

# Enable CORS (configure as needed)
CORS(app, origins=["https://example.com", "https://www.example.com"])  # Restrict origins


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.route('/api', methods=['POST'])  # Changed to POST
@limiter.limit("10 per minute")  # Apply rate limit to this endpoint
@csrf.exempt # Example of exempting a route from CSRF protection (use with caution!)
def api_endpoint():
    """
    API endpoint that retrieves the 'name' value from a JSON payload in the request body.

    Returns:
        JSON response containing the 'name' value, or an error message if the payload is invalid or 'name' is missing.
    """
    try:
        try:
            payload = request.get_json()
        except Exception as e:
            logging.error(f"Invalid JSON payload: {e}")
            return jsonify({'error': 'Invalid JSON payload in request body'}), 400

        if not payload:
            return jsonify({'error': 'No JSON payload provided in request body'}), 400

        if not isinstance(payload, dict):
            return jsonify({'error': 'Payload must be a JSON object (dictionary)'}), 400

        name = payload.get('name')

        if name is None:
            return jsonify({'error': 'Name field is missing in the payload'}), 400

        # Input validation: Whitelist alphanumeric characters and spaces, limit length
        if not re.match(r"^[a-zA-Z0-9\s]{1,50}$", name):
            return jsonify({'error': 'Invalid characters in name field or name too long'}), 400

        return jsonify({'name': name}), 200

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


if __name__ == '__main__':
    #  Do NOT use debug=True in production.  It can expose sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

