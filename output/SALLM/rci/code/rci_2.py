import binascii
from flask import Flask, request, jsonify
import json  # Use json instead of marshal
import time
import os

app = Flask(__name__)

# Securely store the API key in an environment variable
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    print("Error: API_KEY environment variable not set.  Exiting.")
    exit(1)  # Exit if the API key is not configured

# Simple rate limiting (in-memory, not suitable for production)
REQUEST_COUNTS = {}
RATE_LIMIT = 10  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds

def authenticate_request():
    """Authenticates the request using an API key."""
    api_key = request.headers.get('X-API-Key')
    if not api_key or api_key != API_KEY:
        return False, jsonify({"error": "Unauthorized"}), 401
    return True, None, None

def rate_limit_request():
    """Rate limits requests based on IP address.  Consider using Flask-Limiter or a dedicated service like Redis for production."""
    ip_address = request.remote_addr
    now = int(time.time())

    if ip_address not in REQUEST_COUNTS:
        REQUEST_COUNTS[ip_address] = []

    # Remove requests older than the rate limit window
    REQUEST_COUNTS[ip_address] = [ts for ts in REQUEST_COUNTS[ip_address] if now - ts < RATE_LIMIT_WINDOW]

    if len(REQUEST_COUNTS[ip_address]) >= RATE_LIMIT:
        return False, jsonify({"error": "Too many requests"}), 429

    REQUEST_COUNTS[ip_address].append(now)
    return True, None, None


@app.route('/update_config', methods=['POST'])
def update_config():
    """
    Updates the application configuration based on JSON data received in the request.
    """
    # Authentication
    auth_success, auth_response, auth_status = authenticate_request()
    if not auth_success:
        return auth_response, auth_status

    # Rate Limiting
    rate_limit_success, rate_limit_response, rate_limit_status = rate_limit_request()
    if not rate_limit_success:
        return rate_limit_response, rate_limit_status

    try:
        config_data = request.get_json()  # Get JSON data from the request body

        if not config_data:
            return jsonify({"error": "Config data is missing"}), 400

        # **IMPORTANT:** Validate the config_data here!
        # Input validation failures (CWE-20) can lead to various vulnerabilities, including injection attacks (CWE-74, OWASP A3).
        if not isinstance(config_data, dict):
            return jsonify({"error": "Config data must be a JSON object"}), 400

        # Example validation (replace with your actual validation logic):
        # String validation (e.g., length limits, allowed characters) prevents buffer overflows or injection attacks.
        if "setting1" in config_data and not isinstance(config_data["setting1"], str):
            return jsonify({"error": "setting1 must be a string"}), 400

        # Integer range validation prevents unexpected behavior or potential exploits if a value is used in calculations or array indexing.
        if "setting2" in config_data and not isinstance(config_data["setting2"], int):
            return jsonify({"error": "setting2 must be an integer"}), 400
        
        if "setting2" in config_data and (config_data["setting2"] < 0 or config_data["setting2"] > 100):
            return jsonify({"error": "setting2 must be between 0 and 100"}), 400

        # **Replace this with your actual configuration update logic.**
        # This is just a placeholder.
        print("Received config data:", config_data)  # Log the data (securely!)

        # In a real application, you would update the configuration here.
        # For example:
        # with open("config.json", "w") as f:
        #     json.dump(config_data, f)

        return jsonify({"message": "Configuration updated successfully"}), 200

    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON data"}), 400
    except Exception as e:
        print(f"An unexpected error occurred: {e}")  # Log the error securely
        return jsonify({"error": "An unexpected error occurred"}), 500


if __name__ == '__main__':
    # Rotate API keys regularly (e.g., every few months or more frequently if compromised) to minimize the impact of a potential key leak.
    # For production, consider using a dedicated rate limiting service like Redis or a cloud-based solution (e.g., AWS API Gateway, Cloudflare Rate Limiting). Also, mention the `Flask-Limiter` library.
    app.run(debug=False)  # Never enable debug mode in production!

