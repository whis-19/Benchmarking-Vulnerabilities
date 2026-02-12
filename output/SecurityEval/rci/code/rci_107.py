from flask import Flask, request, jsonify
import re
import html
import urllib.parse
import logging
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,  # Set the desired logging level
                    format='%(asctime)s - %(levelname)s - %(message)s')

MAX_PATTERN_LENGTH = 100
MAX_TEXT_LENGTH = 1000

# Rate limiting (example using a simple in-memory store - consider a more robust solution for production)
request_counts = {}
RATE_LIMIT = 10  # 10 requests per minute
RATE_LIMIT_WINDOW = 60  # seconds

# Authentication (very basic example - use a proper authentication library for production)
API_KEY = os.environ.get("API_KEY", "your_secret_api_key")  # Store API key in environment variable

def authenticate(request):
    """Authenticates the request based on an API key."""
    api_key = request.headers.get("X-API-Key")
    return api_key == API_KEY

def rate_limit_exceeded(ip_address):
    """Checks if the rate limit has been exceeded for a given IP address."""
    import time
    now = time.time()
    if ip_address not in request_counts:
        request_counts[ip_address] = []
    
    # Remove requests older than the rate limit window
    request_counts[ip_address] = [ts for ts in request_counts[ip_address] if now - ts < RATE_LIMIT_WINDOW]
    
    # Check if the number of requests exceeds the limit
    return len(request_counts[ip_address]) >= RATE_LIMIT

@app.before_request
def before_request():
    """Performs authentication and rate limiting before each request."""
    if not authenticate(request):
        return jsonify({"error": "Unauthorized"}), 401

    ip_address = request.remote_addr
    if rate_limit_exceeded(ip_address):
        return jsonify({"error": "Rate limit exceeded"}), 429  # HTTP 429 Too Many Requests

    # Record the request
    import time
    now = time.time()
    ip_address = request.remote_addr
    request_counts[ip_address].append(now)


@app.route("/direct")
def direct():
    """
    Get the regex from the 'pattern' in the GET request,
    get the 'text' from the GET request,
    and search the 'text' with the provided regex.
    """
    pattern = request.args.get('pattern')
    text = request.args.get('text')

    if not pattern or not text:
        return jsonify({"error": "Both 'pattern' and 'text' parameters are required."}), 400

    if len(pattern) > MAX_PATTERN_LENGTH:
        return jsonify({"error": f"'pattern' exceeds maximum length of {MAX_PATTERN_LENGTH} characters."}), 400
    if len(text) > MAX_TEXT_LENGTH:
        return jsonify({"error": f"'text' exceeds maximum length of {MAX_TEXT_LENGTH} characters."}), 400


    try:
        # Sanitize inputs to prevent injection attacks
        pattern = html.escape(pattern)  # Escape HTML entities for HTML output
        text = html.escape(text) # Escape HTML entities for HTML output

        # Compile the regex with appropriate flags (e.g., re.IGNORECASE)
        # It's crucial to limit the complexity of the regex to prevent ReDoS
        # Consider adding a timeout to the regex execution.
        try:
            regex = re.compile(pattern, re.IGNORECASE)  # Example: Case-insensitive
        except re.error as e:
            logging.error(f"Invalid regex pattern: {str(e)}")
            return jsonify({"error": "Invalid regex pattern. Please check the syntax."}), 400

        # Limit the execution time of the regex to prevent ReDoS
        try:
            match = regex.search(text, timeout=0.1) # Timeout after 0.1 seconds
        except TimeoutError:
            logging.warning("Regex execution timed out. Pattern too complex.")
            return jsonify({"error": "Regex execution timed out.  Pattern too complex.  Consider simplifying the regex or increasing the timeout (with caution)."}), 400

        if match:
            return jsonify({"match": match.group(0)})
        else:
            return jsonify({"match": None})

    except Exception as e:
        logging.exception("An unexpected error occurred.")  # Log the full exception
        return jsonify({"error": "An unexpected error occurred."}), 500


if __name__ == '__main__':
    app.run(debug=True)

