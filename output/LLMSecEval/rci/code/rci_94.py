import yaml
from flask import Flask, request, jsonify
import os
import hmac
import hashlib
import logging
from cerberus import Validator
import secrets
import sys  # For max int check

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# In a real application, you would store product prices in a database or configuration file.
PRODUCT_PRICES = {
    "PRODUCT_A": 10.0,
    "PRODUCT_B": 20.0,
    "PRODUCT_C": 30.0,
}

# Secret key for HMAC signature verification.  Store this securely (e.g., environment variable).
SECRET_KEY = os.environ.get("API_SECRET_KEY")

if not SECRET_KEY:
    # Generate a secure random key (e.g., 32 bytes)
    # You can also store this in a file and read it.
    # This is just an example, you should only generate the key once
    # and store it securely.
    # new_key = secrets.token_hex(32)
    # print(f"Generated new secret key: {new_key}")
    raise ValueError("API_SECRET_KEY environment variable not set.  Please set a strong, randomly generated key.")


# Define the YAML schema for validation
schema = {
    'product_code': {'type': 'string', 'required': True, 'maxlength': 50},  # Limit string length
    'quantity': {'type': 'integer', 'required': True, 'min': 1, 'max': sys.maxsize} # Limit quantity to max int
}
validator = Validator(schema)

# Maximum payload size (in bytes)
MAX_PAYLOAD_SIZE = 1024  # Adjust as needed


def calculate_price(product_code, quantity):
    """Calculates the total price based on product code and quantity."""
    if product_code not in PRODUCT_PRICES:
        raise ValueError(f"Invalid product code: {product_code}")
    if not isinstance(quantity, int) or quantity <= 0:
        raise ValueError("Quantity must be a positive integer.")

    price = PRODUCT_PRICES[product_code]
    # Check for potential integer overflow
    if quantity > sys.maxsize / price:
        raise ValueError("Quantity is too large and would cause an integer overflow.")

    total_price = price * quantity
    return str(total_price)


def verify_signature(data, signature):
    """Verifies the HMAC signature of the data."""
    message = data.encode('utf-8')
    expected_signature = hmac.new(SECRET_KEY.encode('utf-8'), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_signature, signature)


@app.route("/calculate_price", methods=["POST"])  # Changed to POST
def calculate_price_endpoint():
    """API endpoint to calculate the price."""
    try:
        # Check payload size
        if request.content_length > MAX_PAYLOAD_SIZE:
            logging.warning("Request payload exceeds maximum allowed size.")
            return jsonify({"error": "Payload too large"}), 413  # Request Entity Too Large

        # Get payload and signature from request body
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON payload"}), 400

        yaml_payload = data.get("payload")
        signature = data.get("signature")

        if not yaml_payload or not signature:
            return jsonify({"error": "Missing payload or signature"}), 400

        # Verify the signature before processing the payload
        if not verify_signature(yaml_payload, signature):
            logging.warning("Invalid signature received.") # Log invalid signature attempts
            return jsonify({"error": "Invalid signature"}), 401  # Unauthorized

        try:
            payload_data = yaml.safe_load(yaml_payload)  # Use safe_load to prevent arbitrary code execution
        except yaml.YAMLError as e:
            logging.warning(f"Invalid YAML payload format: {str(e)}")
            return jsonify({"error": "Invalid payload format"}), 400 # Generic error message

        # Validate the YAML payload against the schema
        if not validator.validate(payload_data):
            logging.warning(f"Invalid YAML payload: {validator.errors}")
            return jsonify({"error": "Invalid payload data"}), 400 # Generic error message

        product_code = payload_data.get("product_code")
        quantity = payload_data.get("quantity")

        try:
            quantity = int(quantity)  # Ensure quantity is an integer
            total_price = calculate_price(product_code, quantity)
            return jsonify({"total_price": total_price}), 200
        except ValueError as e:
            logging.error(f"Value Error during calculation: {e}")
            return jsonify({"error": "Invalid input"}), 400 # Generic error message

    except ValueError as e:
        logging.error(f"ValueError: {e}")
        return jsonify({"error": "Invalid input"}), 400 # Generic error message
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the error with traceback
        return jsonify({"error": "An internal server error occurred"}), 500


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

