import os
import secrets
import logging
from flask import Flask, request, jsonify
import yaml
import re  # For input validation
from werkzeug.exceptions import BadRequest  # For custom error handling

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO,  # Set the logging level
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- Secure Secret Management ---
# Generate a random secret key if one doesn't exist.  Store in .env or similar.
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    logger.warning("No SECRET_KEY found in environment. Generating a temporary one.  This is NOT suitable for production.")
    # Consider saving this to a file or environment variable for persistence.
    # WARNING:  Do NOT commit this generated key to version control!
app.config['SECRET_KEY'] = SECRET_KEY

# --- Custom Exception Classes ---
class InvalidProductCodeError(BadRequest):
    """Custom exception for invalid product codes."""
    def __init__(self, message="Invalid product code"):
        super().__init__(message)

class InvalidQuantityError(BadRequest):
    """Custom exception for invalid quantity values."""
    def __init__(self, message="Invalid quantity value"):
        super().__init__(message)

# --- Safe YAML Loading ---
def load_config(filename="config.yaml"):
    """Loads configuration from a YAML file using safe loading."""
    try:
        with open(filename, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {filename}")
        return {}  # Return an empty dictionary or raise an exception as appropriate
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file: {e}")
        return {} # Return an empty dictionary or raise an exception as appropriate

config = load_config()

# --- Input Validation Functions ---
def validate_product_code(product_code):
    """Validates the product code format."""
    if not isinstance(product_code, str) or not re.match(r"^[A-Z0-9]{3}-[A-Z0-9]{3}$", product_code):
        logger.warning(f"Invalid product code format: {product_code}")
        raise InvalidProductCodeError("Product code must be in the format XXX-XXX (alphanumeric, uppercase).")
    return product_code

def validate_quantity(quantity):
    """Validates that the quantity is a positive integer."""
    try:
        quantity = int(quantity)
        if quantity <= 0:
            logger.warning(f"Invalid quantity: {quantity}. Must be a positive integer.")
            raise InvalidQuantityError("Quantity must be a positive integer.")
        return quantity
    except ValueError:
        logger.warning(f"Invalid quantity format: {quantity}. Must be an integer.")
        raise InvalidQuantityError("Quantity must be an integer.")

# --- Route ---
@app.route('/process_order', methods=['POST'])
def process_order():
    """Processes an order, validating inputs and handling errors."""
    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON data received.")
            return jsonify({"error": "No JSON data provided"}), 400

        product_code = data.get('product_code')
        quantity = data.get('quantity')

        # --- Input Validation ---
        try:
            product_code = validate_product_code(product_code)
            quantity = validate_quantity(quantity)
        except (InvalidProductCodeError, InvalidQuantityError) as e:
            return jsonify({"error": str(e)}), 400

        # --- Business Logic (Placeholder) ---
        # In a real application, this would involve database interactions,
        # inventory management, and other business logic.
        logger.info(f"Processing order for product: {product_code}, quantity: {quantity}")
        result = f"Order processed successfully for product: {product_code}, quantity: {quantity}"

        return jsonify({"message": result}), 200

    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        return jsonify({"error": "An unexpected error occurred"}), 500

# --- Health Check Endpoint ---
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "ok"}), 200

# --- Main Execution ---
if __name__ == '__main__':
    # --- Production Readiness ---
    # DO NOT USE debug=True IN PRODUCTION!
    # Use a proper WSGI server like Gunicorn or uWSGI.
    # Example: gunicorn --bind 0.0.0.0:5000 your_app:app
    app.run(debug=False, host='0.0.0.0', port=5000)

# --- Additional Security Considerations (Beyond the Code) ---
# 1.  Regularly update dependencies to patch security vulnerabilities.
# 2.  Use a static code analysis tool (e.g., Bandit, SonarQube) to identify potential security flaws.
# 3.  Implement proper authentication and authorization mechanisms.
# 4.  Use HTTPS to encrypt communication between the client and the server.
# 5.  Implement rate limiting to prevent denial-of-service attacks.
# 6.  Monitor application logs for suspicious activity.
# 7.  Perform regular security audits and penetration testing.
# 8.  Use a Web Application Firewall (WAF) to protect against common web attacks.
# 9.  Implement proper data sanitization and output encoding to prevent XSS attacks.
# 10. Store sensitive data (e.g., passwords, API keys) securely using encryption and access control.

