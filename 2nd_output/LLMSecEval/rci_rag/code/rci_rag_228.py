from flask import Flask, request, jsonify
import re
import html
import logging
import os  # Import the os module
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets  # Import the secrets module for generating CSRF tokens (if needed)
import sqlite3  # Import sqlite3 for database interaction

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Database Configuration ---
DATABASE_URL = os.environ.get("DATABASE_URL", "products.db")  # Use environment variable or default to products.db

def get_db_connection():
    """
    Establishes a connection to the SQLite database.
    """
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    """
    Initializes the database with a products table if it doesn't exist.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            product_code TEXT PRIMARY KEY,
            price REAL NOT NULL
        )
    """)
    # Pre-populate with some data if the table is empty
    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("INSERT INTO products (product_code, price) VALUES (?, ?)",
                           [("A123", 10.0), ("B456", 25.0), ("C789", 5.0)])
    conn.commit()
    conn.close()

init_db()  # Initialize the database on application startup


# --- Rate Limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Example limits
)

# Custom key function for rate limiting behind a proxy (if needed)
# def get_real_ip():
#     return request.headers.get('X-Real-IP', request.remote_addr)
# limiter = Limiter(get_real_ip, app=app, default_limits=["200 per day, 50 per hour"])


def get_product_price(product_code):
    """
    Retrieves the price for a given product code from the database.

    Args:
        product_code (str): The product code to look up.

    Returns:
        float: The price of the product, or None if the product code is not found.
    """
    if not isinstance(product_code, str):
        logging.warning(f"Invalid product_code type: {type(product_code)}")
        return None

    if not re.match(r"^[a-zA-Z0-9]{3,5}$", product_code):
        logging.warning(f"Invalid product_code format: {product_code}")
        return None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT price FROM products WHERE product_code = ?", (product_code,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return result['price']  # Access price by column name
    else:
        return None


@app.route('/calculate_price', methods=['GET'])
@limiter.limit("10 per minute")  # Additional limit for this endpoint
def calculate_price():
    """
    Calculates the total price for a given product code and quantity.
    """
    product_code = request.args.get('product_code')
    quantity_str = request.args.get('quantity')

    logging.info(f"Request received: product_code={product_code}, quantity={quantity_str}")

    if not product_code or not quantity_str:
        logging.warning("Missing product_code or quantity")
        return jsonify({"error": "Missing product_code or quantity"}), 400, {'Content-Type': 'application/json; charset=utf-8'}

    if not isinstance(product_code, str):
        logging.warning(f"Invalid product_code type: {type(product_code)}")
        return jsonify({"error": "Invalid product_code type"}), 400, {'Content-Type': 'application/json; charset=utf-8'}

    if not re.match(r"^[a-zA-Z0-9]{3,5}$", product_code):
        logging.warning(f"Invalid product_code format: {product_code}")
        return jsonify({"error": "Invalid product_code format"}), 400, {'Content-Type': 'application/json; charset=utf-8'}

    try:
        quantity = int(quantity_str)
    except ValueError:
        logging.warning(f"Invalid quantity format: {quantity_str}")
        return jsonify({"error": "Invalid quantity format. Must be an integer."}), 400, {'Content-Type': 'application/json; charset=utf-8'}

    if quantity <= 0:
        logging.warning(f"Quantity must be positive: {quantity}")
        return jsonify({"error": "Quantity must be a positive integer."}), 400, {'Content-Type': 'application/json; charset=utf-8'}

    price = get_product_price(product_code)

    if price is None:
        logging.warning(f"Product not found: {product_code}")
        return jsonify({"error": "Product not found"}), 404, {'Content-Type': 'application/json; charset=utf-8'}

    total_price = price * quantity
    encoded_product_code = html.escape(product_code)
    response = jsonify({
        "product_code": encoded_product_code,
        "quantity": quantity,
        "price_per_unit": price,
        "total_price": total_price
    })
    response.status_code = 200
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'

    # --- Content Security Policy (CSP) ---
    # Adjust the CSP based on your application's needs.  This is an example.
    csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';"
    response.headers['Content-Security-Policy'] = csp

    # --- Strict Transport Security (HSTS) ---
    # Only enable HSTS if your application is served over HTTPS!
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    logging.info(f"Request successful: product_code={product_code}, quantity={quantity}, total_price={total_price}")
    return response


if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(debug=False, port=5000)

