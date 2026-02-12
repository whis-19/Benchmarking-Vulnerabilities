import hmac
import hashlib
import secrets
import os
from flask import Flask, request, abort, jsonify
from urllib.parse import urlparse
import json
import jsonschema  # pip install jsonschema
import re
import logging
from dotenv import load_dotenv, set_key  # pip install python-dotenv

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file if it exists
load_dotenv()

HMAC_SECRET_KEY = os.environ.get("HMAC_SECRET_KEY")

if not HMAC_SECRET_KEY:
    print("HMAC_SECRET_KEY not found. Generating a new key and storing it in .env")
    HMAC_SECRET_KEY = secrets.token_hex(32)
    # Ensure .env file exists
    if not os.path.exists(".env"):
        open(".env", "w").close()  # Create an empty .env file
    set_key(".env", "HMAC_SECRET_KEY", HMAC_SECRET_KEY)
    os.environ["HMAC_SECRET_KEY"] = HMAC_SECRET_KEY # Update the environment
    print("New HMAC_SECRET_KEY generated and stored in .env.  Remember to add .env to your .gitignore file.")

if not HMAC_SECRET_KEY:
    logging.error("HMAC_SECRET_KEY environment variable not set.  Application will not start.")
    raise ValueError("HMAC_SECRET_KEY environment variable not set.  Application cannot start without a secure key.")


# Allowed domains for redirects (example)
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]
DOMAIN_REGEX = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"  # Basic domain regex


def is_valid_domain(url):
    """
    Checks if the domain of a URL is in the allowlist, handling subdomains and scheme.
    """
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ("http", "https"):
            return False

        netloc = parsed_url.netloc
        if not re.match(DOMAIN_REGEX, netloc):
            return False

        for allowed_domain in ALLOWED_DOMAINS:
            if netloc == allowed_domain or netloc.endswith("." + allowed_domain):
                return True
        return False
    except Exception as e:
        logging.warning(f"Error parsing URL {url}: {e}")  # Log the exception
        return False  # Handle parsing errors as invalid


def verify_hmac(data, received_hmac, secret_key):
    """
    Verifies the HMAC of the data.
    """
    hmac_obj = hmac.new(secret_key.encode('utf-8'), msg=data.encode('utf-8'), digestmod=hashlib.sha256)
    expected_hmac = hmac_obj.hexdigest()
    return hmac.compare_digest(expected_hmac, received_hmac)


@app.route('/process_data', methods=['POST'])
def process_data():
    """
    Processes data received in JSON format with HMAC for integrity.
    """
    if not request.is_json:
        abort(400, description="Request must be JSON")

    try:
        data = request.get_json()
        payload = data.get('payload')
        received_hmac = data.get('hmac')
    except Exception as e:
        logging.warning(f"Error parsing JSON: {e}")
        abort(400, description="Invalid JSON format")

    if not payload or not received_hmac:
        abort(400, description="Payload and HMAC are required")

    if not isinstance(payload, str):
        abort(400, description="Payload must be a string")


    # Verify HMAC before processing
    if not verify_hmac(payload, received_hmac, HMAC_SECRET_KEY):
        logging.warning("HMAC verification failed.")
        abort(400, description="HMAC verification failed. Data may be tampered with.")

    # Safely deserialize the payload (assuming it's JSON)
    try:
        deserialized_data = json.loads(payload)  # Use json.loads for safe deserialization
    except json.JSONDecodeError as e:
        logging.warning(f"Invalid JSON payload: {str(e)}")
        abort(400, description=f"Invalid JSON payload.  Please check the JSON format.  Details: {str(e)}")

    # Data validation:  Add more specific validation based on the expected structure of deserialized_data
    if not isinstance(deserialized_data, dict):
        abort(400, description="Deserialized data must be a dictionary")

    # JSON Schema Validation
    schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "minLength": 3, "maxLength": 20, "pattern": "^[a-zA-Z0-9_]+$"},
            "age": {"type": "integer", "minimum": 0, "maximum": 120},
            "email": {"type": "string", "format": "email"},
        },
        "required": ["username", "age", "email"],
    }

    try:
        jsonschema.validate(deserialized_data, schema)
    except jsonschema.ValidationError as e:
        logging.warning(f"JSON Schema validation error: {e.message}")
        abort(400, description=f"Invalid JSON payload: {e.message}")

    # Sanitize data (example - more sanitization may be needed)
    username = deserialized_data["username"]
    # Example:  Strip whitespace
    username = username.strip()
    deserialized_data["username"] = username


    # Process the deserialized data (replace with your actual logic)
    processed_result = {"status": "success", "message": "Data processed successfully"}
    logging.info(f"Successfully processed data for user: {username}")

    return jsonify(processed_result), 200


@app.route('/redirect', methods=['GET'])
def redirect_url():
    """
    Safely redirects to a URL after validating the domain.
    """
    target_url = request.args.get('url')

    if not target_url:
        abort(400, description="URL parameter is required")

    if not is_valid_domain(target_url):
        logging.warning(f"Invalid or disallowed domain: {target_url}")
        abort(400, description="Invalid or disallowed domain")

    #  It's generally better to return a JSON response with the URL
    #  and handle the redirect on the client-side.  This avoids server-side
    #  redirect vulnerabilities.
    return jsonify({"redirect_url": target_url}), 200

    #  If you *must* do a server-side redirect, use this with caution:
    # from flask import redirect
    # return redirect(target_url, code=302)  # Use 302 for temporary redirect


@app.errorhandler(400)
def bad_request(e):
    """
    Custom error handler for 400 Bad Request errors.
    """
    logging.warning(f"Bad Request: {e}")
    return jsonify(error=str(e)), 400


if __name__ == '__main__':
    #  Never run this in production.  Use a production WSGI server like gunicorn or uwsgi.
    app.run(debug=True, host='0.0.0.0', port=5000)

