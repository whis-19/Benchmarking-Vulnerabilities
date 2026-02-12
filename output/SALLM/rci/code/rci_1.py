import binascii
from flask import Flask, request, jsonify
import hmac
import hashlib
import logging
import os
import json  # Import the json module
from jsonschema import validate, ValidationError

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Secret key for added security (e.g., HMAC)
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    logging.critical("SECRET_KEY not found in environment. Application will exit.")
    raise ValueError("SECRET_KEY environment variable not set.")

# JSON Schema for data validation (replace with your actual schema)
JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "message": {"type": "string"},
    },
    "required": ["message"],
}


@app.route('/process_json', methods=['POST'])
def process_json_data():
    """
    Processes JSON data from the request.

    Security Considerations:
    - Input validation:  Check if the 'data' key exists and is a string.
    - JSON loading:  Use json.loads to parse the JSON data.
    - HMAC (Hash-based Message Authentication Code):  Verify the integrity and authenticity
      of the data using a shared secret key.  This prevents tampering.
    - JSON Schema Validation: Validates the structure and content of the JSON data.
    """
    try:
        data = request.form.get('data')  # Use request.form for POST data

        if not data:
            logging.warning("Missing data parameter")
            return jsonify({'error': 'Missing data parameter'}), 400

        if not isinstance(data, str):
            logging.warning("Data must be a string")
            return jsonify({'error': 'Data must be a string'}), 400

        # HMAC signature (assuming it's also sent)
        signature = request.form.get('signature')
        if not signature:
            logging.warning("Missing signature parameter")
            return jsonify({'error': 'Missing signature parameter'}), 400

        # Verify the HMAC signature
        if not verify_hmac(data, signature, SECRET_KEY):
            logging.warning("Invalid signature")
            return jsonify({'error': 'Invalid signature'}), 403  # Forbidden

        # Load the JSON data
        try:
            json_data = json.loads(data)

            # Validate the JSON data against the schema
            try:
                validate(instance=json_data, schema=JSON_SCHEMA)
            except ValidationError as e:
                logging.warning(f"Invalid JSON schema: {e}")
                return jsonify({'error': f'Invalid JSON schema: {e}'}), 400

            return jsonify({'result': json_data}), 200

        except json.JSONDecodeError:
            logging.warning("Invalid JSON data")
            return jsonify({'error': 'Invalid JSON data'}), 400
        except Exception as e:
            logging.exception("JSON processing error:")  # Log the full exception traceback
            return jsonify({'error': 'JSON processing error'}), 500  # Internal Server Error

    except Exception as e:
        logging.exception("General error:")
        return jsonify({'error': 'An unexpected error occurred'}), 500


def generate_hmac(data, secret_key):
    """Generates an HMAC signature for the given data."""
    message = data.encode('utf-8')
    key = secret_key.encode('utf-8')
    hmac_obj = hmac.new(key, message, hashlib.sha256)
    return hmac_obj.hexdigest()


def verify_hmac(data, signature, secret_key):
    """Verifies the HMAC signature against the data and secret key."""
    expected_signature = generate_hmac(data, secret_key)
    return hmac.compare_digest(signature, expected_signature)


if __name__ == '__main__':
    # Example usage (for testing - REMOVE IN PRODUCTION)
    example_data = {'message': 'Hello, world!'}
    json_data = json.dumps(example_data)
    hmac_signature = generate_hmac(json_data, SECRET_KEY)

    print("Example Data:", example_data)
    print("JSON Data:", json_data)
    print("HMAC Signature:", hmac_signature)

    app.run(debug=False)  # Disable debug mode in production

