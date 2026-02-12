import yaml
from flask import Flask, request, jsonify
import secrets
import os

app = Flask(__name__)

# Securely store product prices (ideally in a database or secure configuration)
# Using a dictionary for simplicity in this example.  NEVER hardcode sensitive data.
# Consider using environment variables or a dedicated secrets management solution.
PRODUCT_PRICES = {
    "PRODUCT_A": 10.00,
    "PRODUCT_B": 25.50,
    "PRODUCT_C": 5.75,
}

# Generate a random secret key for Flask (important for security)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(16)
app.config['SECRET_KEY'] = SECRET_KEY


def get_price_for_product_code(product_code):
    """
    Retrieves the price for a given product code.

    Args:
        product_code (str): The product code to look up.

    Returns:
        float: The price of the product, or None if the product code is not found.
    """
    if not isinstance(product_code, str):
        return None  # Or raise an exception:  raise TypeError("product_code must be a string")

    if product_code in PRODUCT_PRICES:
        return PRODUCT_PRICES[product_code]
    else:
        return None  # Or raise an exception: raise ValueError(f"Product code '{product_code}' not found")


@app.route('/calculate_price', methods=['GET'])
def calculate_price():
    """
    Calculates the total price based on a YAML payload provided as a query parameter.

    The YAML payload should contain 'product_code' and 'quantity' keys.

    Returns:
        A YAML payload containing the total price.  Returns an error message if there are issues.
    """
    try:
        yaml_payload = request.args.get('payload')

        if not yaml_payload:
            return jsonify({"error": "Missing 'payload' query parameter."}), 400

        try:
            data = yaml.safe_load(yaml_payload)  # Use safe_load to prevent arbitrary code execution
        except yaml.YAMLError as e:
            return jsonify({"error": f"Invalid YAML payload: {str(e)}"}), 400

        if not isinstance(data, dict):
            return jsonify({"error": "YAML payload must be a dictionary."}), 400

        product_code = data.get('product_code')
        quantity = data.get('quantity')

        if not product_code or not quantity:
            return jsonify({"error": "Missing 'product_code' or 'quantity' in YAML payload."}), 400

        if not isinstance(product_code, str):
            return jsonify({"error": "'product_code' must be a string."}), 400

        if not isinstance(quantity, (int, float)):
            return jsonify({"error": "'quantity' must be a number."}), 400

        if quantity <= 0:
            return jsonify({"error": "'quantity' must be a positive number."}), 400

        price = get_price_for_product_code(product_code)

        if price is None:
            return jsonify({"error": f"Product code '{product_code}' not found."}), 404

        total_price = price * quantity

        response_data = {"total_price": total_price}
        return yaml.dump(response_data, default_flow_style=False), 200, {'Content-Type': 'application/x-yaml'}

    except Exception as e:
        # Log the error for debugging purposes (important in production)
        print(f"An unexpected error occurred: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


if __name__ == '__main__':
    #  DO NOT USE debug=True IN PRODUCTION!  It can expose sensitive information.
    #  Use a proper WSGI server like gunicorn or uWSGI for production deployments.
    app.run(debug=True, host='0.0.0.0', port=5000)

