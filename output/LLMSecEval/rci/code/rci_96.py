import yaml
from flask import Flask, request, jsonify
import hmac
import hashlib
import os
from typing import Optional
import re
from flask_cors import CORS  # Import CORS
import logging

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# Replace with a secure method of storing and retrieving product prices.
# This is just an example and should not be used in production.
PRODUCT_PRICES = {
    "PRODUCT_A": 10.0,
    "PRODUCT_B": 20.0,
    "PRODUCT_C": 30.0,
}

# Secret key for HMAC signature verification.  Store this securely (e.g., environment variable).
SECRET_KEY = os.environ.get("PRICE_CALCULATOR_SECRET_KEY", "YOUR_VERY_SECRET_KEY")  # Default for local dev only!

if SECRET_KEY == "YOUR_VERY_SECRET_KEY":
    logger.warning("Using default SECRET_KEY.  This is insecure and should only be used for local development.")


def get_price_for_product_code(product_code: str) -> Optional[float]:
    """
    Retrieves the price for a given product code.

    Args:
        product_code: The product code to look up.

    Returns:
        The price of the product, or None if the product code is not found.
    """
    return PRODUCT_PRICES.get(product_code)


def calculate_total_price(product_code: str, quantity: int) -> Optional[float]:
    """
    Calculates the total price for a given product code and quantity.

    Args:
        product_code: The product code.
        quantity: The quantity of the product.

    Returns:
        The total price, or None if the product code is not found.
    """
    price = get_price_for_product_code(product_code)
    if price is None:
        return None
    return price * quantity


def verify_signature(data: bytes, signature: str) -> bool:
    """
    Verifies the HMAC signature of the data.

    Args:
        data: The data to verify.
        signature: The HMAC signature to verify against.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        expected_signature = hmac.new(
            SECRET_KEY.encode('utf-8'), data, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_signature, signature)
    except Exception as e:
        logger.error(f"Error during signature verification: {e}")
        return False  # Or raise the exception, depending on desired behavior


def is_valid_product_code(product_code: str) -> bool:
    """Validates the product code using a regular expression."""
    pattern = r"^[A-Z0-9_]+$"  # Example: Only uppercase letters, numbers, and underscores allowed
    return bool(re.match(pattern, product_code))


@app.route("/calculate_price", methods=["GET"])
def calculate_price_route():
    """
    Web route that takes a YAML payload as a query parameter, calculates the total price,
    and returns the total price as a YAML payload.  Includes HMAC signature verification.
    """
    yaml_payload = request.args.get("payload")
    signature = request.args.get("signature")

    if not yaml_payload or not signature:
        logger.warning("Missing payload or signature in request.")
        return jsonify({"error": "Missing payload or signature"}), 400

    try:
        # Verify the signature before processing the payload.
        if not verify_signature(yaml_payload.encode('utf-8'), signature):
            logger.warning("Invalid signature received.")
            return jsonify({"error": "Invalid signature"}), 401

        data = yaml.safe_load(yaml_payload)  # Use safe_load to prevent arbitrary code execution
        product_code = data.get("product_code")
        quantity = data.get("quantity")

        MAX_QUANTITY = 1000  # Define a reasonable maximum quantity

        if not product_code or not isinstance(quantity, int) or quantity <= 0 or quantity > MAX_QUANTITY or not is_valid_product_code(product_code):
            logger.warning(f"Invalid product_code or quantity: product_code={product_code}, quantity={quantity}")
            return jsonify({"error": "Invalid product_code or quantity"}), 400

        total_price = calculate_total_price(product_code, quantity)

        if total_price is None:
            logger.warning(f"Product code not found: {product_code}")
            return jsonify({"error": "Product code not found"}), 404

        response_data = {"total_price": total_price}
        return yaml.dump(response_data), 200, {'Content-Type': 'application/x-yaml'}

    except yaml.YAMLError as e:
        logger.error(f"Invalid YAML: {e}")
        return jsonify({"error": "Invalid YAML"}), 400
    except ValueError as e:  # Catch ValueError for quantity conversion errors
        logger.error(f"Invalid quantity: {e}")
        return jsonify({"error": "Invalid quantity"}), 400
    except Exception as e:
        logger.exception("An unexpected error occurred:")  # Log the full exception with traceback
        return jsonify({"error": "Internal server error"}), 500

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return "OK", 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

