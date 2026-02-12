import re
import os  # For environment variables
import logging
from flask import Flask, request, jsonify, escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]
)

# Configure security headers
talisman = Talisman(app,
                    content_security_policy={
                        'default-src': '\'self\'',
                        'script-src': '\'self\'',
                        'style-src': '\'self\'',
                        'img-src': '\'self\' data:'
                    },
                    force_https=True,
                    frame_options='DENY',
                    x_content_type_options='nosniff',
                    referrer_policy='same-origin',
                    session_cookie_secure=True,
                    session_cookie_httponly=True)


# In-memory product database (replace with a real database for production)
# NEVER HARDCODE SECRETS LIKE THIS IN PRODUCTION
# Use environment variables or a secrets management system
products = {
    "A123": 10.0,
    "B456": 25.50,
    "C789": 5.0
}

class InvalidQuantityError(ValueError):
    pass


def get_price(product_code):
    """
    Returns the price for a given product code.
    Raises ValueError if the product code is invalid or not found.
    """
    if not isinstance(product_code, str):
        raise TypeError("Product code must be a string")

    # Validate product code format (example: alphanumeric, 3-6 characters)
    if not re.match(r"^[a-zA-Z0-9]{3,6}$", product_code):
        raise ValueError("Invalid product code format")

    price = products.get(product_code)
    if price is None:
        raise ValueError("Product not found")

    return price


@app.route('/calculate_price', methods=['GET'])
@limiter.limit("10 per minute")
def calculate_price():
    """
    Calculates the total price for a given product code and quantity.
    """
    product_code = request.args.get('product_code', '').strip()  # Strip whitespace
    quantity_str = request.args.get('quantity', '').strip()  # Strip whitespace

    logging.info(f"Calculate price request for product: {product_code}, quantity: {quantity_str}")

    if not product_code or not quantity_str:
        logging.warning("Missing product_code or quantity")
        return jsonify({"error": "Missing product_code or quantity"}), 400

    try:
        quantity = int(quantity_str)
    except ValueError:
        logging.warning(f"Invalid quantity: {quantity_str}")
        return jsonify({"error": "Invalid quantity. Must be an integer."}), 400

    if quantity <= 0:
        logging.warning(f"Quantity must be positive: {quantity}")
        return jsonify({"error": "Quantity must be positive."}), 400

    if quantity > 1000:
        logging.warning(f"Quantity exceeds maximum allowed: {quantity}")
        return jsonify({"error": "Quantity exceeds maximum allowed (1000)."}), 400

    try:
        price = get_price(product_code)
    except (TypeError, ValueError) as e:
        logging.error(f"Error getting price for product {product_code}: {e}")
        return jsonify({"error": str(e)}), 400


    total_price = price * quantity
    # Escape the product code for safe output in JSON
    escaped_product_code = escape(product_code)

    return jsonify({
        "product_code": escaped_product_code,
        "quantity": quantity,
        "unit_price": price,
        "total_price": total_price
    })


if __name__ == '__main__':
    # Never run with debug=True in production!
    # Use a production WSGI server like Gunicorn or uWSGI
    # Example: gunicorn --bind 0.0.0.0:5000 your_app:app
    app.run(debug=False, host='0.0.0.0', port=5000)

