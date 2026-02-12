from flask import Flask, request, jsonify
import yaml
import os
import logging
from cerberus import Validator
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_talisman import Talisman
import re  # Import the regular expression module
from flask_limiter.errors import RateLimitExceeded

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"],  # Example limits
    storage_uri="redis://localhost:6379"  # Use Redis for storage
)

# Configure CORS
CORS(app, origins=['https://example.com'])  # Restrict to specific origins

# Configure Talisman for security headers
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.example.com'],
    'style-src': ['\'self\'', 'https://fonts.googleapis.com'],
    'font-src': ['\'self\'', 'https://fonts.gstatic.com'],
    'img-src': ['\'self\'', 'data:'],
    'report-uri': '/csp_report'
}
talisman = Talisman(app, content_security_policy=csp)


@app.route('/csp_report', methods=['POST'])
def csp_report():
    logging.warning(f"CSP violation: {request.get_json()}")
    return '', 204

@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429


# Secure YAML loading function
def safe_load_yaml(data):
    """
    Safely loads YAML data using SafeLoader to prevent arbitrary code execution.
    Handles potential errors during loading.
    """
    try:
        # Use SafeLoader to prevent arbitrary code execution
        return yaml.safe_load(data)
    except yaml.YAMLError as e:
        logging.error(f"YAML load error: {e}")  # Log the error for debugging
        return None  # Or raise an exception, depending on desired behavior

class YamlValidationError(Exception):
    def __init__(self, errors):
        self.errors = errors


def validate_yaml_data(data):
    """Validates the parsed YAML data against a schema."""
    schema = {
        'name': {'type': 'string', 'required': True, 'maxlength': 100},
        'age': {'type': 'integer', 'required': True, 'min': 0, 'max': 150},
        'email': {'type': 'string', 'required': False, 'regex': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', 'maxlength': 255},
        'url': {'type': 'string', 'required': False, 'regex': r'^(https?://)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$', 'maxlength': 2048} # Example URL validation
    }
    v = Validator(schema)
    if not v.validate(data):
        raise YamlValidationError(v.errors)
    return True, None


@app.route('/yaml', methods=['POST'])  # Use POST for receiving data
@limiter.limit("10 per minute")  # Specific limit for this endpoint
def yaml_load():
    """
    Get YAML data from request, parse it safely, validate it, and return it as JSON.
    """
    if request.method == 'POST':
        content_type = request.headers.get('Content-Type')
        if content_type not in ('application/x-yaml', 'text/yaml', 'application/yaml'):
            logging.warning(f"Invalid Content-Type: {content_type}")
            return jsonify({"error": "Unsupported Media Type.  Use application/x-yaml or text/yaml"}), 415

        try:
            # Get YAML data from the request body
            yaml_data = request.data.decode('utf-8')  # Decode the data

            # Safely load the YAML data
            parsed_data = safe_load_yaml(yaml_data)

            if parsed_data is None:
                logging.warning("Invalid YAML data received.")
                return jsonify({"error": "Invalid YAML data"}), 400  # Return error if loading fails

            # Validate the parsed data
            validate_yaml_data(parsed_data)


            # Return the parsed data as JSON
            return jsonify(parsed_data), 200

        except YamlValidationError as e:
            logging.warning(f"Invalid YAML data: {e.errors}")
            # Attempt to provide more specific, sanitized error messages
            sanitized_errors = {}
            for field, errors in e.errors.items():
                # Example: Sanitize name length error
                if field == 'name' and any("maxlength" in error for error in errors):
                    sanitized_errors[field] = "Name must be less than 100 characters."
                else:
                    sanitized_errors[field] = "Invalid value." # Generic fallback

            if not sanitized_errors:
                sanitized_errors = {"error": "Invalid data format"} # Fallback if no specific sanitization

            return jsonify({"error": "Invalid YAML data", "details": sanitized_errors}), 400


        except ValueError as ve:
            logging.exception(f"ValueError processing request: {ve}")
            return jsonify({"error": "Invalid data encoding"}), 400
        except Exception as e:
            logging.exception("Error processing request")
            return jsonify({"error": "Internal server error"}), 500  # Generic error message
    else:
        return jsonify({"error": "Method not allowed"}), 405


if __name__ == '__main__':
    #  Use a production-ready WSGI server like Gunicorn or uWSGI in production.
    #  This is just for development.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

