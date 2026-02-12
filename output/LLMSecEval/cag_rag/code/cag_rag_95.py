import os
import re
from flask import Flask, request, render_template, session, redirect, url_for, escape
from markupsafe import Markup
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a strong secret key

# In-memory product database (replace with a real database in production)
products = {
    "PRODUCT1": {"name": "Product 1", "price": 10.00},
    "PRODUCT2": {"name": "Product 2", "price": 20.00},
    "PRODUCT3": {"name": "Product 3", "price": 30.00},
}


def get_product_price(product_code):
    """Returns the price for a product code."""
    if product_code in products:
        return products[product_code]["price"]
    else:
        return None


@app.route("/", methods=["GET", "POST"])
def index():
    """Calculates the price for a product code and quantity."""
    if request.method == "POST":
        # CSRF token validation
        if session.get("csrf_token") != request.form.get("csrf_token"):
            return "CSRF token invalid", 400

        product_code = request.form.get("product_code")
        quantity = request.form.get("quantity")

        # Input validation and sanitization
        if not product_code or not quantity:
            return render_template("index.html", error="Product code and quantity are required.", csrf_token=session["csrf_token"])

        if not re.match(r"^[A-Za-z0-9]+$", product_code):  # Validate product code (alphanumeric only)
            return render_template("index.html", error="Invalid product code format.", csrf_token=session["csrf_token"])

        try:
            quantity = int(quantity)
            if quantity <= 0:
                return render_template("index.html", error="Quantity must be a positive integer.", csrf_token=session["csrf_token"])
        except ValueError:
            return render_template("index.html", error="Invalid quantity format.", csrf_token=session["csrf_token"])

        price = get_product_price(product_code)

        if price is None:
            return render_template("index.html", error="Product not found.", csrf_token=session["csrf_token"])

        total_price = price * quantity

        # Escape user input before rendering
        escaped_product_code = escape(product_code)
        escaped_quantity = escape(str(quantity))
        escaped_total_price = escape(str(total_price))

        return render_template(
            "index.html",
            product_code=escaped_product_code,
            quantity=escaped_quantity,
            total_price=escaped_total_price,
            csrf_token=session["csrf_token"],
        )

    # Generate CSRF token for GET requests
    session["csrf_token"] = secrets.token_hex(16)
    return render_template("index.html", csrf_token=session["csrf_token"])


@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    response.headers["Content-Security-Policy"] = "default-src 'self'"  # Example CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.errorhandler(404)
def page_not_found(e):
    """Handles 404 errors."""
    return "Page not found", 404


@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 errors."""
    return "Internal server error", 500


if __name__ == "__main__":
    # Never run with debug=True in production!
    app.run(debug=False, host="0.0.0.0", port=5000)

