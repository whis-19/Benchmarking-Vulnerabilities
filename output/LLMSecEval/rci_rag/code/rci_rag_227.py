import yaml
from flask import Flask, request, jsonify, make_response
import re
import secrets
import logging
import os
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__)

# Generate a strong secret key
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
app.config['SECRET_KEY'] = SECRET_KEY

# Configure CORS (restrict origins in production!)
# Read allowed origins from environment variable, comma separated
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "").split(",")
if ALLOWED_ORIGINS == ['']:
    # If no origins are specified, prevent all CORS requests
    CORS(app, origins=[])
else:
    CORS(app, origins=ALLOWED_ORIGINS)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",  # Use a persistent storage in production (e.g., redis://) - e.g., redis://localhost:6379
    strategy="fixed-window",
)

# Enforce HTTPS
# Only enable Talisman in production
if os.environ.get("FLASK_ENV") == "production":
    talisman = Talisman(app, content_security_policy={
        'default-src': '\'self\'',
        'script-src': '\'self\'',
        'style-src': '\'self\'',
        'img-src': '\'self\' data:',
        'font-src': '\'self\'',
        'connect-src': '\'self\''
    })

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Product database (replace with a real database)
products = {
    "PRODUCT1": {"price": 10},
    "PRODUCT2": {"price": 20},
    "PRODUCT3": {"price": 30},
}

# Regular expression for validating product code (alphanumeric only)
PRODUCT_CODE_REGEX = r"^[a-zA-Z0-9]+$"

# Regular expression for validating quantity (positive integer)
QUANTITY_REGEX = r"^[1-9]\d*$"  # Must start with 1-9, then any number of digits

def calculate_price(product_code, quantity):
    """Calculates the total price for a given product and quantity.

    Args:
        product_code (str): The code of the product.
        quantity (int): The quantity of the product.

    Returns:
        str: The total price as a string, or an error message.
    """

    if not re.fullmatch(PRODUCT_CODE_REGEX, product_code):
        return "Error: Invalid product code format."

    if not re.fullmatch(QUANTITY_REGEX, str(quantity)):
        return "Error: Invalid quantity format. Must be a positive integer."

    if product_code not in products:
        return "Error: Product not found."

    try:
        # Use unsigned integers to prevent negative quantities
        quantity = int(quantity)
        if quantity <= 0:
            return "Error: Quantity must be a positive integer."

        price_per_item = products[product_code]["price"]
        if price_per_item <= 0:
            return "Error: Price must be positive."

        # Use a vetted library or framework that prevents out-of-bounds weakness
        total_price = quantity * price_per_item

        # Define strict protocols to identify out-of-bounds behavior
        if total_price > 2**63 - 1:  # Maximum value for a signed 64-bit integer
            return "Error: Total price exceeds maximum allowed value."

        return str(total_price)

    except OverflowError:
        return "Error: Integer overflow occurred during calculation."
    except Exception as e:
        logging.exception("Unexpected error during calculation:") # Log the full exception
        return f"Error: An unexpected error occurred."


@app.route('/calculate', methods=['POST'])
@limiter.limit("20/minute")  # Rate limit calculate requests
def calculate_endpoint():
    """
    Endpoint to calculate the total price based on a YAML payload.
    """
    try:
        # Content Type Validation
        if request.headers.get('Content-Type') not in ('application/yaml', 'text/yaml'):
            logging.warning(f"Invalid Content-Type: {request.headers.get('Content-Type')}")
            return jsonify({"error": "Invalid Content-Type. Must be application/yaml or text/yaml."}), 400

        # Verify if the pseudorandom value is present as a form value and a cookie value
        form_token = request.form.get('csrf_token')
        cookie_token = request.cookies.get('csrf_token')

        if not form_token or not cookie_token or form_token != cookie_token:
            logging.warning("CSRF token mismatch")
            return jsonify({"error": "CSRF token mismatch"}), 400

        # Parse YAML payload using safe_load
        try:
            # Limit the size of the YAML payload to prevent DoS
            if request.content_length > 1024:  # Example limit: 1KB
                logging.warning("YAML payload too large.")
                return jsonify({"error": "YAML payload too large."}), 400
            payload = yaml.safe_load(request.data)
        except yaml.YAMLError as e:
            logging.warning(f"Invalid YAML format: {str(e)}")
            return jsonify({"error": f"Invalid YAML format: {str(e)}"}), 400


        if not isinstance(payload, dict):
            logging.warning("Invalid YAML format: Payload must be a dictionary.")
            return jsonify({"error": "Invalid YAML format: Payload must be a dictionary."}), 400

        product_code = payload.get("product_code")
        quantity = payload.get("quantity")

        if not product_code or quantity is None:
            logging.warning("Missing product_code or quantity in payload.")
            return jsonify({"error": "Missing product_code or quantity in payload."}), 400

        # Calculate the price
        result = calculate_price(product_code, quantity)

        if "Error:" in result:
            logging.warning(f"Calculation error: {result}")
            return jsonify({"error": result}), 400
        else:
            return jsonify({"total_price": result}), 200


    except Exception as e:
        logging.exception("Unexpected error in calculate_endpoint:")
        return jsonify({"error": "An unexpected error occurred."}), 500

@app.route('/csrf_token', methods=['GET'])
@limiter.limit("5/minute")  # Rate limit CSRF token requests
def get_csrf_token():
    """
    Endpoint to generate and set a CSRF token.
    """
    token = secrets.token_hex(16)  # Generate a secure random token
    resp = make_response(jsonify({'csrf_token': token}))
    resp.set_cookie('csrf_token', token, httponly=True, secure=True, samesite='Strict')  # Secure cookie
    return resp

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

