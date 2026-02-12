import yaml
from flask import Flask, request, jsonify, make_response, render_template_string
import secrets
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # For CSRF protection (using Flask-WTF or similar)

# In-memory product database (replace with a real database)
product_prices = {
    "PRODUCT1": 10.0,
    "PRODUCT2": 20.0,
    "PRODUCT3": 30.0,
}

# CSRF protection (using double-submit cookie method)
def generate_csrf_token():
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure, HttpOnly, and SameSite attributes
    return csrf_token

def verify_csrf_token(request):
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_form = request.form.get('csrf_token')

    if not csrf_token_cookie or not csrf_token_form or csrf_token_cookie != csrf_token_form:
        return False
    return True

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            if not verify_csrf_token(request):
                return jsonify({'error': 'CSRF token validation failed'}), 400
        return f(*args, **kwargs)
    return decorated_function

def get_price_for_product_code(product_code):
    """
    Returns the price for a given product code.  Returns None if the product code is not found.
    """
    return product_prices.get(product_code)

@app.route('/calculate_price', methods=['POST'])
@csrf_protect
def calculate_price():
    """
    Calculates the total price based on a YAML payload containing product code and quantity.
    """
    try:
        # Validate Content-Type
        if request.content_type != 'application/x-yaml':
            return jsonify({'error': 'Invalid Content-Type.  Must be application/x-yaml'}), 400

        # Load YAML payload safely
        payload = yaml.safe_load(request.data)

        if not isinstance(payload, dict):
            return jsonify({'error': 'Invalid YAML payload. Must be a dictionary.'}), 400

        # Extract product code and quantity
        product_code = payload.get('product_code')
        quantity = payload.get('quantity')

        # Validate input data
        if not isinstance(product_code, str):
            return jsonify({'error': 'Invalid product_code. Must be a string.'}), 400
        if not isinstance(quantity, int) or quantity <= 0:
            return jsonify({'error': 'Invalid quantity. Must be a positive integer.'}), 400

        # Get the price for the product code
        price = get_price_for_product_code(product_code)

        if price is None:
            return jsonify({'error': f'Product code "{product_code}" not found.'}), 400

        # Calculate the total price
        total_price = price * quantity

        # Return the total price as a YAML payload
        response_data = {'total_price': total_price}
        response = make_response(yaml.dump(response_data))
        response.headers['Content-Type'] = 'application/x-yaml'
        return response

    except yaml.YAMLError as e:
        return jsonify({'error': f'Invalid YAML format: {str(e)}'}), 400
    except Exception as e:
        print(f"An unexpected error occurred: {e}") # Log the error for debugging
        return jsonify({'error': 'An unexpected error occurred.'}), 500

@app.route('/form', methods=['GET'])
def form():
    """
    Serves a simple HTML form with CSRF protection.
    """
    csrf_token = generate_csrf_token()
    resp = make_response(render_template_string('''
        <form method="post" action="/calculate_price">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label for="yaml_data">YAML Data:</label><br>
            <textarea id="yaml_data" name="yaml_data" rows="4" cols="50">
product_code: PRODUCT1
quantity: 2
            </textarea><br>
            <input type="submit" value="Calculate Price">
        </form>
    ''', csrf_token=csrf_token))
    set_csrf_cookie(resp)
    return resp

if __name__ == '__main__':
    # Never run this in production.  Use a proper WSGI server.
    app.run(debug=True, host='0.0.0.0', port=5000)

