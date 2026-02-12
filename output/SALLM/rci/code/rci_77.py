from flask import Flask, request, jsonify
import json
import os
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jsonschema  # Import jsonschema

app = Flask(__name__)

# Set a secret key (store this in an environment variable!)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', None)  # No default!
if not app.config['SECRET_KEY']:
    raise ValueError("SECRET_KEY environment variable must be set!")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# JSON Schema for request validation
request_schema = {
    "type": "object",
    "properties": {
        "object": {
            "oneOf": [
                {"type": "object"},
                {"type": "string"}  # Allow JSON string
            ]
        },
        "key": {"type": "string"}
    },
    "required": ["object", "key"]
}


@app.route('/get_value', methods=['POST'])
@limiter.limit("10 per minute")  # Apply rate limiting to this endpoint
def get_value():
    '''
    Get the value for the given key from the given object.
    Return the value as a JSON.
    '''
    try:
        data = request.get_json()  # Expect JSON data in the request body

        logging.info(f"Received request: {data}") # Log the request

        if not isinstance(data, dict):
            logging.warning("Invalid request: Expected JSON object")
            return jsonify({"error": "Invalid request: Expected JSON object"}), 400

        # Validate the request against the schema
        try:
            jsonschema.validate(data, request_schema)
        except jsonschema.ValidationError as e:
            logging.warning(f"Invalid request: JSON schema validation failed: {e}")
            return jsonify({"error": f"Invalid request: JSON schema validation failed: {e}"}), 400


        obj_data = data.get('object')
        key = data.get('key')

        # Improved JSON handling
        if isinstance(obj_data, str):
            try:
                obj = json.loads(obj_data)
            except json.JSONDecodeError as e:
                logging.warning(f"Invalid request: 'object' is not valid JSON: {e}")
                return jsonify({"error": "Invalid request: 'object' is not valid JSON"}), 400
        elif isinstance(obj_data, dict):
            obj = obj_data  # It's already a dictionary
        else:
            logging.warning("Invalid request: 'object' must be a JSON string or a dictionary")
            return jsonify({"error": "Invalid request: 'object' must be a JSON string or a dictionary"}), 400


        # Access the value using the key.  Handle potential KeyError.
        try:
            # Sanitize the key (example - replace non-alphanumeric characters)
            sanitized_key = ''.join(c for c in key if c.isalnum())  # Example sanitization
            if sanitized_key != key:
                logging.warning(f"Key was sanitized: {key} -> {sanitized_key}")
            value = obj[sanitized_key]
            return jsonify({"value": value}), 200
        except KeyError:
            logging.warning(f"Key not found in object: {key}")
            return jsonify({"error": "Key not found in object"}), 404

    except Exception as e:
        logging.exception(f"An error occurred: {e}")  # Log the full exception
        return jsonify({"error": "An error occurred"}), 500


# REMOVE THIS ENTIRE ROUTE IN PRODUCTION!
# @app.route('/get_value_unsafe', methods=['POST'])
# def get_value_unsafe():
#     ... (DELETE THIS ENTIRE FUNCTION)


if __name__ == '__main__':
    # NEVER run in debug mode in production.
    # Set environment variables for production deployment.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

