import yaml
from flask import Flask, request, jsonify, make_response
import secrets
import hashlib
import hmac
import os
import sqlite3  # Using SQLite for simplicity; consider a more robust database in production
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # For CSRF and other security features

# Initialize SQLite database (in-memory for this example)
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
            product_code TEXT PRIMARY KEY,
            price REAL NOT NULL
        )
    ''')
    # Example data (replace with your actual product data)
    cursor.execute("INSERT OR IGNORE INTO products (product_code, price) VALUES (?, ?)", ('PRODUCT1', 10.0))
    cursor.execute("INSERT OR IGNORE INTO products (product_code, price) VALUES (?, ?)", ('PRODUCT2', 20.0))
    conn.commit()
    conn.close()

init_db()


# CSRF protection (simplified example)
def generate_csrf_token():
    return secrets.token_hex(16)

def validate_csrf_token(token):
    # In a real application, store tokens server-side (e.g., in a session)
    # and compare against the stored token.  This is a simplified example.
    return True  # Replace with actual validation logic

def csrf_protected(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get('X-CSRF-Token')  # Or from form data
        if not token or not validate_csrf_token(token):
            return jsonify({'error': 'CSRF token validation failed'}), 403
        return fn(*args, **kwargs)
    return wrapper


def get_price_for_product_code(product_code):
    """Retrieves the price for a given product code from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Use parameterized query to prevent SQL injection
    cursor.execute("SELECT price FROM products WHERE product_code = ?", (product_code,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return row['price']
    else:
        return None


def calculate_hmac(data, secret_key):
    """Calculates an HMAC for data integrity."""
    key = secret_key.encode('utf-8')
    message = data.encode('utf-8')
    hmac_obj = hmac.new(key, message, hashlib.sha256)
    return hmac_obj.hexdigest()


@app.route('/calculate_price', methods=['POST'])
@csrf_protected  # Apply CSRF protection
def calculate_price():
    """Calculates the total price based on a YAML payload."""
    try:
        # Get YAML payload from request body
        yaml_payload = request.get_data(as_text=True)

        # Validate data before deserialization (basic check)
        if not isinstance(yaml_payload, str) or len(yaml_payload) > 1000:  # Limit payload size
            return jsonify({'error': 'Invalid payload'}), 400

        # Safely load YAML using yaml.safe_load
        try:
            data = yaml.safe_load(yaml_payload)
        except yaml.YAMLError as e:
            return jsonify({'error': f'Invalid YAML: {str(e)}'}), 400

        # Input validation: Check if data is a dictionary and contains required keys
        if not isinstance(data, dict) or 'product_code' not in data or 'quantity' not in data:
            return jsonify({'error': 'Invalid YAML format.  Must contain product_code and quantity.'}), 400

        product_code = data.get('product_code')
        quantity = data.get('quantity')

        # Input validation: Sanitize and validate product_code and quantity
        if not isinstance(product_code, str) or not product_code.isalnum() or len(product_code) > 20:
            return jsonify({'error': 'Invalid product_code. Must be alphanumeric and less than 20 characters.'}), 400

        if not isinstance(quantity, (int, float)) or quantity <= 0 or quantity > 1000:  # Limit quantity
            return jsonify({'error': 'Invalid quantity. Must be a positive number and less than 1000.'}), 400


        # Get price from database
        price = get_price_for_product_code(product_code)

        if price is None:
            return jsonify({'error': 'Product not found'}), 404

        # Calculate total price
        total_price = price * quantity

        # Create response data
        response_data = {'total_price': total_price}

        # Serialize to YAML
        response_yaml = yaml.dump(response_data)

        # Calculate HMAC for integrity
        hmac_value = calculate_hmac(response_yaml, app.config['SECRET_KEY'])

        # Add HMAC to response headers
        response = make_response(response_yaml)
        response.headers['Content-Type'] = 'application/x-yaml'
        response.headers['X-HMAC'] = hmac_value

        return response, 200

    except Exception as e:
        print(f"Error: {e}")  # Log the error for debugging
        return jsonify({'error': 'An unexpected error occurred.'}), 500


@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


if __name__ == '__main__':
    app.run(debug=True)  # Disable debug mode in production

