import re
from flask import Flask, request, jsonify, escape
import secrets
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

# In-memory product database (replace with a real database for production)
products = {
    "PRODUCT123": {"name": "Example Product", "price": 25.00},
    "PRODUCT456": {"name": "Another Product", "price": 50.00},
    "PRODUCT789": {"name": "Yet Another Product", "price": 75.00}
}


def get_product_price(product_code):
    """
    Retrieves the price for a given product code.

    Args:
        product_code (str): The product code to look up.

    Returns:
        float: The price of the product, or None if the product is not found.
    """
    if not isinstance(product_code, str):
        return None

    # Validate product code using a regular expression
    if not re.match(r"^[A-Z0-9]+$", product_code):
        return None

    product = products.get(product_code)
    if product:
        return product["price"]
    else:
        return None


@app.route("/calculate_price", methods=["GET"])
def calculate_price():
    """
    Calculates the total price for a given product code and quantity.
    """
    product_code = request.args.get("product_code")
    quantity_str = request.args.get("quantity")

    # Input validation
    if not product_code or not quantity_str:
        return jsonify({"error": "Missing product_code or quantity"}), 400

    # Validate product code using a regular expression
    if not re.match(r"^[A-Z0-9]+$", product_code):
        return jsonify({"error": "Invalid product_code format"}), 400

    # Validate quantity using a regular expression and convert to integer
    if not re.match(r"^[1-9]\d*$", quantity_str):  # Only positive integers allowed
        return jsonify({"error": "Invalid quantity format. Must be a positive integer."}), 400

    try:
        quantity = int(quantity_str)
    except ValueError:
        return jsonify({"error": "Invalid quantity format"}), 400

    price = get_product_price(product_code)

    if price is None:
        return jsonify({"error": "Product not found"}), 404

    total_price = price * quantity
    # Escape the product code for safe output in JSON
    escaped_product_code = escape(product_code)

    return jsonify({
        "product_code": escaped_product_code,
        "quantity": quantity,
        "unit_price": price,
        "total_price": total_price
    })


@app.route("/", methods=["GET"])
def home():
    """
    A simple home route to demonstrate escaping.
    """
    user_input = request.args.get("input", "")
    escaped_input = escape(user_input)
    return f"<h1>Welcome!</h1><p>You entered: {escaped_input}</p>"


if __name__ == "__main__":
    # Never run with debug=True in production!
    app.run(debug=False, host="0.0.0.0", port=5000)

