import yaml
from flask import Flask, request, jsonify, make_response, render_template
import secrets
import os
from functools import wraps
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = secrets.token_hex(16)  # For CSRF protection
app.jinja_env.autoescape = True  # Enable autoescaping for Jinja2 templates

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# Talisman for security headers
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',  # Consider adding nonces or hashes.  Using 'self' is generally good.
    'style-src': '\'self\'',   # Consider adding nonces or hashes.  Using 'self' is generally good.
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'object-src': '\'none\'',
    'report-uri': '/csp_report',  # Add a report URI for CSP violations
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src', 'style-src'],  # Enable nonces if using inline scripts/styles
    force_https=True,  # Enforce HTTPS
    frame_options='DENY',
    x_content_type_options='nosniff',
    referrer_policy='same-origin',
)


# In-memory product database (replace with a real database)
product_prices = {
    "PRODUCT123": 10.0,
    "PRODUCT456": 25.0,
    "PRODUCT789": 5.0,
}

# CSRF protection using double-submit cookie method
def generate_csrf_token():
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
    return csrf_token

def verify_csrf_token(request):
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_header = request.headers.get('X-CSRF-Token')  # Or form data

    if not csrf_token_cookie or not csrf_token_header or csrf_token_cookie != csrf_token_header:
        return False
    return True

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':  # Only protect POST requests
            if not verify_csrf_token(request):
                return jsonify({'error': 'CSRF token validation failed'}), 400
        return f(*args, **kwargs)
    return decorated_function


def get_price_for_product_code(product_code):
    """Returns the price for a product code."""
    if not isinstance(product_code, str):
        return None

    product_code = product_code.strip().upper()  # Normalize and sanitize
    if not product_code.isalnum():  # Consider allowing hyphens/underscores if needed
        return None

    return product_prices.get(product_code)


def is_valid_origin(origin):
    """Validates the origin of the request."""
    allowed_origins = os.environ.get("ALLOWED_ORIGINS", "http://example.com,https://example.com").split(",")
    allowed_origins = [o.strip() for o in allowed_origins]
    return origin in allowed_origins


@app.route('/calculate_price', methods=['POST'])
@csrf_protect
@limiter.limit("10 per minute")
def calculate_price():
    """Calculates the total price based on a YAML payload."""
    origin = request.headers.get('Origin')

    if not origin:
        logging.warning("No Origin header present.  Rejecting request.")
        return jsonify({'error': 'No Origin header'}), 403

    if not is_valid_origin(origin):
        logging.warning(f"Invalid Origin: {origin}")
        return jsonify({'error': 'Invalid origin'}), 403

    try:
        payload = yaml.safe_load(request.data)

        if not isinstance(payload, dict):
            return jsonify({'error': 'Invalid YAML format: Must be a dictionary'}), 400

        product_code = payload.get('product_code')
        quantity = payload.get('quantity')

        if not isinstance(product_code, str):
            return jsonify({'error': 'Invalid product_code: Must be a string'}), 400
        if not isinstance(quantity, int) or quantity <= 0:
            return jsonify({'error': 'Invalid quantity: Must be a positive integer'}), 400

        price = get_price_for_product_code(product_code)

        if price is None:
            return jsonify({'error': f'Product code {product_code} not found'}), 404

        total_price = price * quantity

        response_data = {'total_price': total_price}
        response = make_response(yaml.dump(response_data, encoding='utf-8'))  # Explicit UTF-8
        response.headers['Content-Type'] = 'application/x-yaml'
        return response

    except yaml.YAMLError as e:
        return jsonify({'error': f'Invalid YAML: {str(e)}'}), 400
    except Exception as e:
        logging.exception("An unexpected error occurred")
        return jsonify({'error': 'An internal error occurred'}), 500


@app.route('/form', methods=['GET'])
def form():
    """Serves a simple form with CSRF protection."""
    csrf_token = generate_csrf_token()
    response = make_response(render_template('form.html', csrf_token=csrf_token))
    set_csrf_cookie(response)
    return response


@app.route('/csp_report', methods=['POST'])
def csp_report():
    """Endpoint for receiving CSP reports."""
    logging.warning(f"CSP Violation: {request.get_json()}")
    return '', 204


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

