import yaml
from flask import Flask, request, jsonify, abort
import os
from dotenv import load_dotenv

app = Flask(__name__)

# Load environment variables (for example, from a .env file)
load_dotenv()

# In-memory product database (replace with a real database in production)
products = {
    "PRODUCT1": {"price": 10.0},
    "PRODUCT2": {"price": 20.0},
    "PRODUCT3": {"price": 30.0},
}

# CSP Header - Adjust as needed for your application's requirements
csp_header = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',  # Allow scripts only from the same origin
    'style-src': '\'self\' \'unsafe-inline\'',  # Allow styles from the same origin and inline styles (use with caution)
    'img-src': '\'self\' data:',  # Allow images from the same origin and data URIs
    'font-src': '\'self\'',  # Allow fonts from the same origin
    'connect-src': '\'self\'',  # Allow connections only to the same origin
    'frame-src': '\'self\'',  # Allow frames only from the same origin
}

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = '; '.join(f"{k} {v}" for k, v in csp_header.items())
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


def validate_product_code(product_code):
    """Validates that the product code exists in the database."""
    if not isinstance(product_code, str):
        return False, "Product code must be a string."
    if product_code not in products:
        return False, "Invalid product code."
    return True, None


def validate_quantity(quantity):
    """Validates that the quantity is a positive integer."""
    if not isinstance(quantity, int):
        return False, "Quantity must be an integer."
    if quantity <= 0:
        return False, "Quantity must be a positive integer."
    return True, None


@app.route('/calculate_price', methods=['GET'])
def calculate_price():
    """
    Calculates the total price based on the product code and quantity provided in the YAML payload.
    """
    try:
        yaml_payload = request.args.get('payload')

        if not yaml_payload:
            return jsonify({"error": "Payload is required"}), 400

        try:
            # Use safe_load to prevent arbitrary code execution
            data = yaml.safe_load(yaml_payload)
        except yaml.YAMLError as e:
            return jsonify({"error": f"Invalid YAML payload: {str(e)}"}), 400

        if not isinstance(data, dict):
            return jsonify({"error": "Payload must be a dictionary"}), 400

        product_code = data.get('product_code')
        quantity = data.get('quantity')

        # Input validation
        valid_product, product_error = validate_product_code(product_code)
        if not valid_product:
            return jsonify({"error": product_error}), 400

        valid_quantity, quantity_error = validate_quantity(quantity)
        if not valid_quantity:
            return jsonify({"error": quantity_error}), 400

        # Calculate the total price
        price_per_item = products[product_code]["price"]
        total_price = price_per_item * quantity

        return jsonify({"total_price": str(total_price)}), 200

    except Exception as e:
        print(f"An unexpected error occurred: {e}")  # Log the error for debugging
        return jsonify({"error": "An unexpected error occurred"}), 500


if __name__ == '__main__':
    #  Never expose this to the public internet in production.
    #  Use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, host='127.0.0.1', port=5000)

