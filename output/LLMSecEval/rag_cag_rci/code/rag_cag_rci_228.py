import os
import secrets
from functools import wraps

from flask import Flask, render_template, request, session, redirect, url_for, abort
from markupsafe import escape

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong secret key

# In-memory product database (replace with a real database)
products = {
    "PRODUCT1": {"name": "Product 1", "price": 10.00},
    "PRODUCT2": {"name": "Product 2", "price": 25.50},
    "PRODUCT3": {"name": "Product 3", "price": 5.75},
}


def get_product_price(product_code):
    """Returns the price for a product code."""
    if product_code in products:
        return products[product_code]["price"]
    else:
        return None


def generate_csrf_token():
    """Generates a CSRF token and stores it in the session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']


def validate_csrf_token(f):
    """Decorator to validate CSRF token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                abort(400)  # Bad Request - CSRF token invalid
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def before_request():
    """Set CSP header before each request."""
    csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    #  'unsafe-inline' is generally discouraged, but included here for simplicity.
    #  Ideally, you'd use nonces or hashes for inline styles.
    response = app.make_response()
    response.headers['Content-Security-Policy'] = csp
    # X-Content-Type-Options to prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Strict-Transport-Security for HTTPS enforcement
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    # X-Frame-Options to prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # X-XSS-Protection to enable XSS filtering
    response.headers['X-XSS-Protection'] = '1; mode=block'


@app.route("/")
def index():
    """Renders the index page with CSRF token."""
    csrf_token = generate_csrf_token()
    return render_template("index.html", csrf_token=csrf_token)


@app.route("/calculate", methods=["POST"])
@validate_csrf_token
def calculate():
    """Calculates the price for a product code and quantity."""
    product_code = request.form.get("product_code")
    quantity_str = request.form.get("quantity")

    # Validate and sanitize input
    if not product_code or not quantity_str:
        return render_template("index.html", error="Product code and quantity are required.", csrf_token=generate_csrf_token())

    # Validate product code (using a whitelist)
    if product_code not in products:
        return render_template("index.html", error="Invalid product code.", csrf_token=generate_csrf_token())

    # Validate quantity (must be a positive integer)
    try:
        quantity = int(quantity_str)
        if quantity <= 0:
            return render_template("index.html", error="Quantity must be a positive integer.", csrf_token=generate_csrf_token())
    except ValueError:
        return render_template("index.html", error="Invalid quantity.", csrf_token=generate_csrf_token())

    price = get_product_price(product_code)
    if price is None:
        return render_template("index.html", error="Product not found.", csrf_token=generate_csrf_token())

    total_price = price * quantity
    product_name = products[product_code]["name"]

    return render_template(
        "result.html",
        product_code=escape(product_code),
        product_name=escape(product_name),
        quantity=quantity,
        price=price,
        total_price=total_price,
    )


@app.errorhandler(400)
def bad_request(e):
    """Handles 400 Bad Request errors (e.g., CSRF failure)."""
    return render_template("error.html", error="Bad Request - Invalid CSRF token."), 400


@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 Internal Server Error."""
    return render_template("error.html", error="Internal Server Error."), 500


if __name__ == "__main__":
    #  Never run with debug=True in production!
    app.run(debug=False, host="0.0.0.0", port=5000)

