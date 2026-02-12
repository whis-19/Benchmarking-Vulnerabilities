import yaml
from flask import Flask, request, jsonify, render_template_string
from markupsafe import escape

app = Flask(__name__)

# In-memory product database (replace with a real database)
products = {
    "PRODUCT1": {"price": 10.0},
    "PRODUCT2": {"price": 20.0},
    "PRODUCT3": {"price": 30.0},
}

# CSP Policy - Adjust as needed for your application
csp_policy = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',  # Allow scripts from the same origin
    'style-src': '\'self\'',   # Allow styles from the same origin
    'img-src': '\'self\' data:',  # Allow images from the same origin and data URIs
    'font-src': '\'self\'',    # Allow fonts from the same origin
    'object-src': '\'none\'',  # Disallow object/embed elements
    'base-uri': '\'self\'',    # Restrict base URL
    'form-action': '\'self\'', # Restrict form submissions
}

def generate_csp_header(policy):
    """Generates a Content-Security-Policy header string."""
    return '; '.join(f"{k} {v}" for k, v in policy.items())


@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    response.headers['Content-Security-Policy'] = generate_csp_header(csp_policy)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


def calculate_price(product_code, quantity):
    """Calculates the total price based on product code and quantity."""
    if not isinstance(product_code, str):
        raise ValueError("Product code must be a string.")
    if not isinstance(quantity, (int, float)):
        raise ValueError("Quantity must be a number.")
    if quantity <= 0:
        raise ValueError("Quantity must be positive.")

    product_code = product_code.upper()  # Standardize product code

    if product_code not in products:
        raise ValueError(f"Invalid product code: {escape(product_code)}")

    price = products[product_code]["price"]
    total_price = price * quantity
    return str(total_price)


@app.route("/calculate", methods=["GET"])
def calculate_price_api():
    """
    API endpoint to calculate the total price based on a YAML payload.
    """
    try:
        yaml_payload = request.args.get("payload")

        if not yaml_payload:
            return jsonify({"error": "Missing payload parameter"}), 400

        # Validate YAML before parsing
        try:
            # Attempt to load the YAML to check for syntax errors
            yaml.safe_load(yaml_payload)
        except yaml.YAMLError as e:
            return jsonify({"error": f"Invalid YAML: {escape(str(e))}"}), 400

        try:
            data = yaml.safe_load(yaml_payload)  # Safe YAML loading
        except yaml.YAMLError as e:
            return jsonify({"error": f"YAML parsing error: {escape(str(e))}"}), 400

        if not isinstance(data, dict):
            return jsonify({"error": "Payload must be a YAML dictionary"}), 400

        product_code = data.get("product_code")
        quantity = data.get("quantity")

        if not product_code or not quantity:
            return jsonify({"error": "Missing product_code or quantity in payload"}), 400

        # Input validation
        if not isinstance(product_code, str):
            return jsonify({"error": "product_code must be a string"}), 400
        if not isinstance(quantity, (int, float)):
            return jsonify({"error": "quantity must be a number"}), 400

        try:
            total_price = calculate_price(product_code, quantity)
            return jsonify({"total_price": total_price}), 200
        except ValueError as e:
            return jsonify({"error": str(escape(e))}), 400

    except Exception as e:
        print(f"An unexpected error occurred: {e}")  # Log the error
        return jsonify({"error": "An unexpected error occurred"}), 500


@app.route("/")
def index():
    """Simple index page with a form to submit YAML payload."""
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Price Calculator</title>
    </head>
    <body>
        <h1>Price Calculator</h1>
        <form action="/calculate" method="GET">
            <label for="payload">YAML Payload:</label><br>
            <textarea id="payload" name="payload" rows="4" cols="50">
product_code: PRODUCT1
quantity: 2
            </textarea><br><br>
            <input type="submit" value="Calculate">
        </form>
    </body>
    </html>
    """
    return render_template_string(template)


if __name__ == "__main__":
    #  Never use debug=True in production.
    #  Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=False, host="0.0.0.0", port=5000)

