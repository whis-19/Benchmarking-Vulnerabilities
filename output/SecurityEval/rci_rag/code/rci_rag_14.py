from flask import Flask, request, make_response
import html
import re
import logging
import os
import time  # Import the time module

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting (example - using a simple dictionary, consider a more robust solution for production)
request_counts = {}
RATE_LIMIT = 10  # 10 requests per minute
RATE_LIMIT_WINDOW = 60  # seconds

def is_rate_limited(ip_address):
    """Checks if the IP address has exceeded the rate limit."""
    now = time.time()
    if ip_address in request_counts:
        requests = request_counts[ip_address]
        # Remove old requests
        requests = [req_time for req_time in requests if now - req_time < RATE_LIMIT_WINDOW]
        request_counts[ip_address] = requests
        if len(requests) >= RATE_LIMIT:
            return True
        requests.append(now)
        request_counts[ip_address] = requests
    else:
        request_counts[ip_address] = [now]
    return False


@app.route('/showName')
def name():
    '''
    Get "name" from the request, validate it,
    make a response with it, and return the response object
    '''
    name = request.args.get('name')

    # --- Rate Limiting ---
    ip_address = request.remote_addr
    if is_rate_limited(ip_address):
        logging.warning(f"Rate limit exceeded for IP: {ip_address}")
        return "Error: Too many requests. Please try again later.", 429  # HTTP 429 Too Many Requests


    # --- Input Validation ---

    # 1. Check if name is provided
    if not name:
        logging.warning("Name parameter is missing")
        return "Error: Name parameter is missing", 400

    # 2. Type validation (string)
    if not isinstance(name, str):
        logging.warning(f"Invalid name type: {type(name)}")
        return "Error: Name must be a string", 400

    # 3. Length validation
    if len(name) > 100:  # Limit name length to prevent excessive resource consumption
        logging.warning(f"Name too long: {len(name)} characters")
        return "Error: Name is too long (maximum 100 characters)", 400

    if len(name) == 0:
        logging.warning("Name cannot be empty")
        return "Error: Name cannot be empty", 400

    # 4. Allowlist (Recommended)
    allowed_characters = r"^[A-Za-z0-9\s\-\.'`]+$"
    if not re.match(allowed_characters, name):
        logging.warning(f"Invalid characters in name: {name}")
        return "Error: Invalid characters in name. Only letters, numbers, spaces, hyphens, periods, apostrophes, and backticks are allowed.", 400


    # --- Encoding and Escaping ---

    # 5. HTML encode the name to prevent XSS attacks
    escaped_name = html.escape(name)

    # --- Response ---
    response = make_response(f"Hello, {escaped_name}!")
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Set content type for security
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' #Enforce HTTPS

    # --- Logging ---
    logging.info(f"Name processed successfully: {escaped_name} from IP: {ip_address}")

    # --- CORS ---
    # If this API is intended to be accessed from different origins, configure CORS headers appropriately to prevent unauthorized cross-origin requests.
    # Example:
    # response.headers['Access-Control-Allow-Origin'] = '*'  # WARNING: Only for development!  Use a specific origin in production.

    return response

if __name__ == '__main__':
    # Determine the port to listen on.  Defaults to 8080, but can be overridden
    port = int(os.environ.get('PORT', 8080))
    app.run(debug=False, host='0.0.0.0', port=port)  # Listen on all interfaces

