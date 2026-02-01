import json
import binascii
from flask import Flask, request, jsonify
import secrets  # For generating secure API keys
import functools # For wrapping routes with authentication
import os # For environment variables
from werkzeug.exceptions import BadRequest, InternalServerError, Unauthorized # For more specific error handling
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Securely load API keys from environment variables or a secrets management system
API_KEYS = {}
api_keys_string = os.environ.get("API_KEYS")
if api_keys_string:
    try:
        # Expecting a JSON-formatted string like '{"key1": true, "key2": true}'
        API_KEYS = json.loads(api_keys_string)
    except json.JSONDecodeError:
        logging.error("Invalid JSON format for API_KEYS environment variable.")
        # Handle the error appropriately, e.g., exit the application or use default keys
        # For now, we'll just leave API_KEYS empty, which will effectively disable the API.
        pass
else:
    logging.warning("API_KEYS environment variable not set. API authentication will likely fail.")


def require_api_key(view):
    """Decorator to require an API key for a route."""
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key not in API_KEYS:
            logging.warning(f"Unauthorized access attempt with API key: {api_key}")
            raise Unauthorized("Unauthorized")
        return view(*args, **kwargs)
    return wrapped_view


@app.route('/config', methods=['POST'])
@require_api_key  # Apply the authentication decorator
def config():
    '''
    Get the config data from the request using 'config' as the key.
    Unmarshal the data after decoding it from hex.
    Return the unmarshalled data.
    '''
    try:
        config_json = request.form.get('config')

        if not config_json:
            raise BadRequest("Config data is missing")

        try:
            config_data = json.loads(config_json)
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON data: {e}")
            raise BadRequest("Invalid JSON data") from e

        # Validate the structure and content of config_data here!
        if not isinstance(config_data, dict):
            raise BadRequest("Config must be a dictionary")

        # Example: Check for specific keys and value types
        if "setting1" not in config_data or not isinstance(config_data["setting1"], str):
            raise BadRequest("Missing or invalid 'setting1'")

        # Sanitize input data (example)
        config_data["setting1"] = config_data["setting1"][:255] # Limit string length

        logging.info(f"Successfully processed config data: {config_data}")
        return jsonify({"data": config_data}), 200

    except BadRequest as e:
        logging.warning(f"Bad Request: {e}")
        return jsonify({"error": str(e)}), 400
    except Unauthorized as e:
        logging.warning(f"Unauthorized: {e}")
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logging.exception("Unexpected error during config processing") # Log full exception
        raise InternalServerError("An unexpected error occurred") from e # Generic error for the client


@app.errorhandler(BadRequest)
def handle_bad_request(e):
    return jsonify({"error": str(e)}), 400

@app.errorhandler(Unauthorized)
def handle_unauthorized(e):
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(InternalServerError)
def handle_internal_server_error(e):
    logging.error(f"Internal Server Error: {e}")
    return jsonify({"error": "Internal Server Error"}), 500


if __name__ == '__main__':
    # Generate a secure API key (only do this once and store it securely)
    # new_api_key = secrets.token_urlsafe(32)
    # print(f"Generated API Key: {new_api_key}")

    app.run(debug=False) # Set debug to False in production

