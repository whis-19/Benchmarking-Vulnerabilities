import yaml
from flask import Flask, request, jsonify, render_template_string
from markupsafe import escape

app = Flask(__name__)

# In-memory product database (replace with a real database)
products = {
    "PRODUCT1": {"price": 10.0},
    "PRODUCT2": {"price": 20.0},
}

#  CSRF protection (very basic example - use a proper library like Flask-WTF)
csrf_token = "YOUR_CSRF_TOKEN"  # Replace with a dynamically generated token

@app.route('/calculate_price', methods=['GET', 'POST'])
def calculate_price():
    """
    Calculates the total price based on product code and quantity from a YAML payload.
    """
    if request.method == 'POST':
        # CSRF protection (basic example)
        if request.form.get('csrf_token') != csrf_token:
            return jsonify({"error": "CSRF token invalid"}), 400

        try:
            yaml_payload = request.form.get('payload')  # Get YAML from form data
            if not yaml_payload:
                return jsonify({"error": "YAML payload is missing"}), 400

            # Validate YAML before deserialization
            if not isinstance(yaml_payload, str):
                return jsonify({"error": "Invalid YAML payload type"}), 400

            # Safe YAML loading
            try:
                data = yaml.safe_load(yaml_payload)
            except yaml.YAMLError as e:
                return jsonify({"error": f"Invalid YAML format: {str(e)}"}), 400

            # Input validation
            if not isinstance(data, dict):
                return jsonify({"error": "YAML payload must be a dictionary"}), 400

            product_code = data.get("product_code")
            quantity = data.get("quantity")

            # Validate product_code
            if not isinstance(product_code, str):
                return jsonify({"error": "Product code must be a string"}), 400
            product_code = escape(product_code)  # Escape for output

            # Validate quantity
            if not isinstance(quantity, (int, float)):
                return jsonify({"error": "Quantity must be a number"}), 400
            if quantity <= 0:
                return jsonify({"error": "Quantity must be positive"}), 400

            # Check if product exists
            if product_code not in products:
                return jsonify({"error": "Invalid product code"}), 400

            # Calculate price
            price = products[product_code]["price"]
            total_price = price * quantity

            return jsonify({"total_price": str(total_price)})

        except Exception as e:
            return jsonify({"error": f"An error occurred: {str(e)}"}), 500

    # Render a simple form for POST requests (with CSRF token)
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Calculate Price</title>
        </head>
        <body>
            <h1>Calculate Price</h1>
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <label for="payload">YAML Payload:</label><br>
                <textarea id="payload" name="payload" rows="4" cols="50"></textarea><br><br>
                <input type="submit" value="Calculate">
            </form>
        </body>
        </html>
        """, csrf_token=csrf_token)


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

