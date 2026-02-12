import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import hmac
import hashlib
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import logging  # Import the logging module

# Load environment variables from .env file (if it exists)
load_dotenv()

app = Flask(__name__)

# Initialize Talisman for security headers
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'frame-ancestors': '\'none\'',
    # Add other CSP directives as needed for your application
}, force_https=True)  # Enforce HTTPS

# Configure logging
logging.basicConfig(level=logging.INFO,  # Set the logging level
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379",  # Use Redis for production
)


# Securely store product prices (ideally in a database)
PRODUCT_PRICES = {
    "PRODUCT_A": 10.0,
    "PRODUCT_B": 25.0,
    "PRODUCT_C": 5.0,
}

# Secret key for HMAC (must be kept secret and securely stored)
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    logging.critical("FATAL: SECRET_KEY environment variable not set. Application cannot start.")
    raise ValueError("FATAL: SECRET_KEY environment variable not set. Application cannot start.")


def get_product_price(product_code):
    """
    Retrieves the price for a given product code.

    Args:
        product_code (str): The product code.

    Returns:
        float: The price of the product, or None if the product code is not found.
    """
    if not isinstance(product_code, str):
        return None

    product_code = product_code.upper()

    if product_code in PRODUCT_PRICES:
        return PRODUCT_PRICES[product_code]
    else:
        return None


def calculate_price(product_code, quantity):
    """
    Calculates the total price for a given product code and quantity.

    Args:
        product_code (str): The product code.
        quantity (int): The quantity of the product.

    Returns:
        float: The total price, or None if the product code is not found or quantity is invalid.
    """
    price = get_product_price(product_code)
    if price is None:
        return None

    if not isinstance(quantity, int) or quantity <= 0:
        return None

    return price * quantity


def canonicalize_json(data):
    """Canonicalizes JSON data by sorting keys and removing whitespace."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'))


@app.route("/price", methods=["POST"])
@limiter.limit("5/minute")
def price_route():
    """
    Calculates the price for a product code and quantity, and returns the result as JSON.
    Requires HMAC authentication.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400

        product_code = data.get("product_code")
        quantity = data.get("quantity")
        signature = request.headers.get("X-Signature")

        # Validate input data types
        if not isinstance(product_code, str) or not isinstance(quantity, int):
            return jsonify({"error": "Invalid input data types. Product code must be a string and quantity must be an integer."}), 400

        # Validate product_code and quantity
        product_code = product_code.upper()
        if product_code not in PRODUCT_PRICES:
            return jsonify({"error": "Invalid product code"}), 400

        if quantity <= 0 or quantity > 1000:
            return jsonify({"error": "Invalid quantity. Must be between 1 and 1000."}), 400

        # Validate HMAC signature
        if not signature:
            return jsonify({"error": "Missing signature"}), 401

        # Canonicalize the JSON data
        canonicalized_data = canonicalize_json(data)

        # Verify the signature
        expected_signature = hmac.new(SECRET_KEY.encode('utf-8'), canonicalized_data.encode('utf-8'), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            return jsonify({"error": "Invalid signature"}), 401

        price = calculate_price(product_code, quantity)

        if price is None:
            return jsonify({"error": "Invalid product code or quantity"}), 400

        return jsonify({"price": price}), 200

    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format"}), 400
    except Exception as e:
        logging.exception("Error processing request")  # Logs traceback to the logging system
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

