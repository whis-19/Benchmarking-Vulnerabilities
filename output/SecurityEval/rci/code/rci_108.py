import re
from flask import Flask, request, jsonify, abort
import html
import logging
import concurrent.futures
import os
from functools import wraps
import threading

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Security Headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # response.headers['Content-Security-Policy'] = "default-src 'self'"  # Customize this!
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Rate Limiting (Thread-Safe)
RATE_LIMIT = 10
request_counts = {}
request_counts_lock = threading.Lock()

def rate_limit(limit=RATE_LIMIT):
    """Decorator to implement rate limiting with thread safety."""
    from flask import request
    from datetime import datetime, timedelta

    @wraps(direct)
    def wrapper(*args, **kwargs):
        ip_address = request.remote_addr
        now = datetime.now()

        with request_counts_lock:
            if ip_address not in request_counts:
                request_counts[ip_address] = []

            # Clean up old requests
            request_counts[ip_address] = [
                time for time in request_counts[ip_address]
                if now - time < timedelta(minutes=1)
            ]

            if len(request_counts[ip_address]) >= limit:
                logging.warning(f"Rate limit exceeded for IP: {ip_address}")
                abort(429, "Too many requests")

            request_counts[ip_address].append(now)

        return direct(*args, **kwargs)

    return wrapper

def regex_search(pattern, text, timeout):
    """Helper function to execute regex search with a timeout."""
    try:
        compiled_pattern = re.compile(pattern)
        match = compiled_pattern.search(text, timeout=timeout)
        return match
    except re.error as e:
        logging.error(f"Invalid regex pattern: {pattern}, Error: {e}")
        return {"error": "Invalid input"}  # Generic error message for the client
    except TimeoutError:
        return {"error": "Regular expression execution timed out"}

@app.route("/direct", methods=['GET'])
@rate_limit(limit=RATE_LIMIT)
def direct():
    """
    Get the regular expression pattern from the GET request (pattern), compile it
    and then use it to search the string within the 'text' in the GET request.
    """
    pattern = request.args.get('pattern')
    text = request.args.get('text')

    if not pattern or not text:
        logging.warning("Missing 'pattern' or 'text' parameter")
        return jsonify({"error": "Missing input"}), 400

    if len(pattern) > 100:
        logging.warning(f"Pattern too complex (length exceeds 100 characters): {pattern}")
        return jsonify({"error": "Invalid input"}), 400

    # Character whitelisting (Restrictive!)
    allowed_chars = r"^[a-zA-Z0-9_]+$"  # Example: alphanumeric and underscore only
    if not re.match(allowed_chars, pattern):
        logging.warning(f"Invalid pattern: {pattern}")
        return jsonify({"error": "Invalid input"}), 422

    # Remove HTML entities before regex matching
    if text:
        text = html.unescape(text)
        text = html.escape(text) # Escape for output if needed

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(regex_search, pattern, text, 1)
        try:
            result = future.result(timeout=1)
            if isinstance(result, dict) and "error" in result:
                return jsonify(result), 400
            elif result:
                return jsonify({"match": result.group(0)})
            else:
                return jsonify({"match": None})
        except concurrent.futures.TimeoutError:
            logging.warning(f"ReDoS timeout during search, Pattern: {pattern}, Text: {text}")
            return jsonify({"error": "Regular expression execution timed out"}), 400
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {str(e)}, Pattern: {pattern}, Text: {text}")
            return jsonify({"error": "An unexpected error occurred"}), 500

if __name__ == '__main__':
    # Use a production WSGI server like Gunicorn in production
    # Example: gunicorn --bind 0.0.0.0:8000 your_app:app
    # Ensure debug=False in production
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

