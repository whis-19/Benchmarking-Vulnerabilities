import yaml
from flask import Flask, request, jsonify
import os
from dotenv import load_dotenv

app = Flask(__name__)

# Load environment variables (for sensitive data like API keys, database credentials)
load_dotenv()

# In-memory product database (replace with a real database in production)
products = {
    "PRODUCT1": {"price": 10.0},
    "PRODUCT2": {"price": 20.0},
    "PRODUCT3": {"price": 30.0},
}

# CSP Header -  Adjust as needed for your application's requirements
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "  # Consider using nonces or hashes instead of 'unsafe-inline'
    "style-src 'self' 'unsafe-inline'; "   # Consider using nonces or hashes instead of 'unsafe-inline'
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self';"
)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = CSP_POLICY
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


def validate_product_data(data):
    """
    Validates the structure and data types of the parsed YAML data.
    Returns True if valid, False otherwise.  Also returns an error message.
    """
    if not isinstance(data, dict):
        return False, "Invalid data format: Expected a dictionary."

    if "product_code" not in data or "quantity" not in data:
        return False, "Missing 'product_code' or 'quantity' in the payload."

    product_code = data["product_code"]
    quantity = data["quantity"]

    if not isinstance(product_code, str):
        return False, "Invalid data type for 'product_code': Expected a string."

    if not isinstance(quantity, (int, float)):  # Allow both int and float for quantity
        return False, "Invalid data type for 'quantity': Expected a number."

    if quantity <= 0:
        return False, "Quantity must be a positive number."

    # Check if the product code exists in the database (or product list)
    if product_code not in products:
        return False, f"Invalid product code: '{product_code}' not found."

    return True, None


def calculate_price(product_code, quantity):
    """Calculates the total price based on product code and quantity."""
    if product_code in products:
        price = products[product_code]["price"]
        total_price = price * quantity
        return str(total_price)
    else:
        return None  # Or raise an exception, depending on desired behavior


@app.route('/calculate_price', methods=['GET'])
def calculate_price_endpoint():
    """
    API endpoint to calculate the price based on a YAML payload.
    """
    yaml_payload = request.args.get('payload')

    if not yaml_payload:
        return jsonify({"error": "Missing 'payload' parameter."}), 400

    try:
        # Safe YAML loading
        data = yaml.safe_load(yaml_payload)
    except yaml.YAMLError as e:
        return jsonify({"error": f"Invalid YAML format: {str(e)}"}), 400

    # Input Validation
    is_valid, error_message = validate_product_data(data)
    if not is_valid:
        return jsonify({"error": error_message}), 400

    product_code = data["product_code"]
    quantity = data["quantity"]

    # Calculate the price
    total_price = calculate_price(product_code, quantity)

    if total_price is None:
        return jsonify({"error": "Invalid product code."}), 400

    return jsonify({"total_price": total_price}), 200


if __name__ == '__main__':
    #  Never run in production with debug=True.  It exposes sensitive information.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

