import yaml
from flask import Flask, request, jsonify, make_response, render_template
import secrets
import os
from functools import wraps
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3  # Import for SQLite database
from flask_cors import CORS  # Import for CORS

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # For session management (CSRF protection)
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure session cookies are only sent over HTTPS
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB limit for YAML payload

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize CORS (configure as needed)
CORS(app)  # Allow all origins by default.  Restrict in production.

# Database setup (using SQLite for simplicity)
DATABASE = 'product_prices.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            code TEXT PRIMARY KEY,
            price REAL NOT NULL
        )
    ''')
    # Pre-populate with some data (only if the table is empty)
    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("INSERT INTO products (code, price) VALUES (?, ?)",
                           [("PRODUCT123", 10.0), ("PRODUCT456", 25.50), ("PRODUCT789", 5.0)])
    conn.commit()
    conn.close()

init_db()  # Initialize the database when the app starts

# CSRF protection using double-submit cookie method
def generate_csrf_token():
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure and Strict for production
    return csrf_token

def verify_csrf_token(request):
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_form = request.form.get('csrf_token')

    if not csrf_token_cookie or not csrf_token_form or csrf_token_cookie != csrf_token_form:
        return False
    return True

def csrf_protected(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == 'POST':
            if not verify_csrf_token(request):
                logger.warning("CSRF token validation failed")
                return jsonify({'error': 'Invalid request'}), 400  # Generic error
        return fn(*args, **kwargs)
    return wrapper

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)


def get_price_for_product_code(product_code):
    """
    Retrieves the price for a given product code from the database.

    Args:
        product_code (str): The product code to look up.

    Returns:
        float: The price of the product, or None if the product code is not found.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT price FROM products WHERE code = ?", (product_code,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result['price']  # Access price by column name
    return None


@app.route('/calculate_price', methods=['POST'])
@csrf_protected
@limiter.limit("10 per minute")  # Apply rate limiting to the endpoint
def calculate_price():
    """
    Calculates the total price based on a YAML payload containing product code and quantity.
    Expects a POST request with YAML data in the body.

    Returns:
        A YAML payload containing the total price.  Returns an error message if there are issues.
    """
    try:
        # Validate Content-Type
        if request.content_type != 'application/x-yaml':
            logger.warning(f"Invalid Content-Type: {request.content_type}")
            return jsonify({'error': 'Invalid request'}), 400  # Generic error

        # Load YAML data safely
        try:
            payload = yaml.safe_load(request.data)
        except yaml.YAMLError as e:
            logger.warning(f"Invalid YAML: {str(e)}")
            return jsonify({'error': 'Invalid request'}), 400  # Generic error


        if not isinstance(payload, dict):
            logger.warning(f"Invalid YAML format: {payload}")
            return jsonify({'error': 'Invalid request'}), 400  # Generic error

        product_code = payload.get('product_code')
        quantity = payload.get('quantity')

        # Validate input data
        if not isinstance(product_code, str):
            logger.warning(f"Invalid product_code type: {type(product_code)}")
            return jsonify({'error': 'Invalid request'}), 400  # Generic error

        # Sanitize product code (example: remove leading/trailing whitespace)
        product_code = product_code.strip()

        if not isinstance(quantity, (int, float)):
            logger.warning(f"Invalid quantity type: {type(quantity)}")
            return jsonify({'error': 'Invalid request'}), 400  # Generic error
        if quantity <= 0:
            logger.warning(f"Invalid quantity value: {quantity}")
            return jsonify({'error': 'Invalid request'}), 400  # Generic error

        # Get the price for the product code
        price = get_price_for_product_code(product_code)

        if price is None:
            logger.warning(f'Product code "{product_code}" not found.')
            return jsonify({'error': 'Product not found'}), 404  # Generic error

        # Calculate the total price
        total_price = price * quantity

        # Return the total price as a YAML payload
        response_data = {'total_price': total_price}
        response = make_response(yaml.dump(response_data))
        response.headers['Content-Type'] = 'application/x-yaml'
        logger.info(f"Calculated price for product {product_code}: {total_price}")
        return response

    except Exception as e:
        # Log the error for debugging purposes (in a real application)
        logger.exception("An unexpected error occurred")  # Log the full exception
        return jsonify({'error': 'An error occurred'}), 500  # Generic error


@app.route('/form', methods=['GET'])
def form():
    """
    Serves a simple HTML form for submitting the YAML payload.  Includes CSRF protection.
    """
    csrf_token = generate_csrf_token()
    resp = make_response(render_template('form.html', csrf_token=csrf_token))
    set_csrf_cookie(resp)
    return resp


if __name__ == '__main__':
    # Never run this in production.  Use a proper WSGI server.
    # Use environment variables for configuration in production
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

