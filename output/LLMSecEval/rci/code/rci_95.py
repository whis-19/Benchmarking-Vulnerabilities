import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import hmac
import hashlib
import json
import time
import redis  # Example: Using Redis for persistent storage
import threading

# Load environment variables from .env file (if it exists)
load_dotenv()

app = Flask(__name__)

# Securely store product prices (ideally in a database)
# Using a dictionary for simplicity, but consider a database for production
PRODUCT_PRICES = {
    "PRODUCT_A": 10.0,
    "PRODUCT_B": 25.0,
    "PRODUCT_C": 5.0,
}

# Secret key for HMAC (must be kept secret and securely stored)
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    print("ERROR: SECRET_KEY not found in environment.  Application will not start.")
    exit(1)  # Exit the application

MAX_TIMESTAMP_AGE = 30  # Seconds - adjust as needed
MAX_PRODUCT_CODE_LENGTH = 50
MAX_QUANTITY = 1000

# Redis configuration (replace with your actual Redis settings)
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_DB = int(os.environ.get("REDIS_DB", 0))

try:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
    redis_client.ping()  # Check Redis connection
    print("Connected to Redis successfully.")
except redis.exceptions.ConnectionError as e:
    print(f"ERROR: Could not connect to Redis: {e}. Replay protection will not function.")
    redis_client = None  # Disable Redis functionality
    # Consider exiting if Redis is critical: exit(1)

# Lock for thread-safe access to Redis (if needed)
redis_lock = threading.Lock()


def is_replay_attack(timestamp: str) -> bool:
    """Checks if the timestamp has been used recently using Redis."""
    if redis_client is None:
        print("WARNING: Redis is not configured. Replay protection is disabled.")
        return False  # Or raise an exception if replay protection is critical

    try:
        with redis_lock:  # Acquire the lock
            return redis_client.exists(f"timestamp:{timestamp}")
    except redis.exceptions.ConnectionError as e:
        print(f"ERROR: Redis connection error: {e}. Replay protection may be bypassed.")
        return False  # Or raise an exception if replay protection is critical


def add_timestamp(timestamp: str):
    """Adds the timestamp to Redis with an expiration time."""
    if redis_client is None:
        print("WARNING: Redis is not configured. Replay protection is disabled.")
        return

    try:
        with redis_lock:  # Acquire the lock
            redis_client.setex(f"timestamp:{timestamp}", MAX_TIMESTAMP_AGE, "used")  # Set with expiration
    except redis.exceptions.ConnectionError as e:
        print(f"ERROR: Redis connection error: {e}.  Failed to add timestamp to Redis.")


# Example of using SafeInt (replace with actual implementation if available)
def safe_multiply(a: float, b: int) -> float | None:
    """Safely multiplies two numbers, preventing overflow."""
    MAX_SAFE_INTEGER = 2**53 - 1  # Maximum safe integer in JavaScript (often used as a limit)
    try:
        result = a * b
        if abs(result) > MAX_SAFE_INTEGER:
            raise OverflowError("Integer overflow detected")
        return result
    except OverflowError:
        return None  # Or raise an exception, depending on your needs


def get_product_price(product_code: str) -> float | None:
    """
    Retrieves the price for a given product code.

    Args:
        product_code (str): The product code.

    Returns:
        float: The price of the product, or None if the product code is not found.
    """
    if not isinstance(product_code, str):
        return None  # Prevent type errors

    product_code = product_code.upper()  # Standardize product codes

    if product_code in PRODUCT_PRICES:
        return PRODUCT_PRICES[product_code]
    else:
        return None


def calculate_price(product_code: str, quantity: int) -> float | None:
    """
    Calculates the total price for a given product code and quantity.

    Args:
        product_code (str): The product code.
        quantity (int): The quantity of the product.

    Returns:
        float: The total price, or None if the product code is not found or quantity is invalid.
    """
    price = get_product_price(product_code)
    if price is None:
        return None

    if not isinstance(quantity, int) or quantity <= 0:
        return None  # Prevent invalid quantities

    total_price = safe_multiply(price, quantity)
    return total_price


@app.route("/price", methods=["POST"])
def price_route():
    """
    Calculates the price for a product code and quantity, and returns the result as JSON.
    Requires HMAC authentication.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON data"}), 400

        product_code = data.get("product_code")
        quantity = data.get("quantity")
        timestamp = data.get("timestamp")
        signature = request.headers.get("X-Signature")  # Get the signature from the header

        # Validate input data types
        if not isinstance(product_code, str) or not isinstance(quantity, int) or not isinstance(timestamp, (int, float, str)):
            return jsonify({"error": "Invalid input data types. Product code must be a string, quantity must be an integer, and timestamp must be a number or string."}), 400

        # Input Validation
        if not isinstance(product_code, str) or len(product_code) > MAX_PRODUCT_CODE_LENGTH:
            return jsonify({"error": f"Product code too long. Maximum length is {MAX_PRODUCT_CODE_LENGTH} characters."}), 400

        if not isinstance(quantity, int) or quantity > MAX_QUANTITY:
            return jsonify({"error": f"Quantity too large. Maximum quantity is {MAX_QUANTITY}."}), 400

        # Validate timestamp format and range
        try:
            timestamp_float = float(timestamp)
            if timestamp_float < 0:  # Unix timestamps are non-negative
                return jsonify({"error": "Invalid timestamp: must be a non-negative number."}), 400
        except ValueError:
            return jsonify({"error": "Invalid timestamp: must be a number."}), 400

        # Validate HMAC signature
        if not signature:
            return jsonify({"error": "Missing signature"}), 401

        # Replay protection
        now = time.time()
        if now - timestamp_float > MAX_TIMESTAMP_AGE:
            return jsonify({"error": "Timestamp is too old"}), 401

        if is_replay_attack(str(timestamp)):  # Convert timestamp to string for Redis
            return jsonify({"error": "Replay attack detected"}), 401

        # Reconstruct the message used to generate the signature
        message_dict = {"product_code": product_code, "quantity": quantity, "timestamp": timestamp}
        message_json = json.dumps(message_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')

        # Verify the signature
        expected_signature = hmac.new(SECRET_KEY.encode('utf-8'), message_json, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            return jsonify({"error": "Invalid signature"}), 401

        add_timestamp(str(timestamp))  # Convert timestamp to string for Redis

        price = calculate_price(product_code, quantity)

        if price is None:
            return jsonify({"error": "Invalid product code or quantity"}), 400

        if price is None:
            return jsonify({"error": "Integer overflow detected"}), 400

        return jsonify({"price": price}), 200

    except Exception as e:
        print(f"Error processing request: {type(e).__name__}: {str(e)}")  # Log the error for debugging
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    #  Never run in debug mode in production.
    app.run(debug=False, host="0.0.0.0", port=5000)

