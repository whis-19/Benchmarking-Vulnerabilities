from flask import request, Flask, make_response, abort
import re
import os
from urllib.parse import quote

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # Limit request size to 10MB
app.config['SECRET_KEY'] = os.urandom(24) # Required for session management

# Rate limiting (example - adapt to your needs)
REQUEST_LIMIT = 10
request_counts = {}

def is_rate_limited(ip_address):
    """Checks if the IP address has exceeded the request limit."""
    if ip_address not in request_counts:
        request_counts[ip_address] = 0
    request_counts[ip_address] += 1
    return request_counts[ip_address] > REQUEST_LIMIT

@app.before_request
def before_request():
    """Applies security measures before each request."""
    ip_address = request.remote_addr
    if is_rate_limited(ip_address):
        abort(429)  # Too Many Requests

    # Validate headers (example - add more as needed)
    if 'User-Agent' not in request.headers:
        abort(400) # Bad Request

    # Validate URL (example - restrict allowed characters)
    if not re.match(r"^[a-zA-Z0-9/\-]+$", request.path):
        abort(400)

@app.after_request
def after_request(response):
    """Sets security headers after each request."""
    response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Example CSP

    # Set HttpOnly flag for session cookie (if using sessions)
    # response.set_cookie('session', value='...', httponly=True, secure=True, samesite='Lax') # Example
    return response


@app.route("/direct")
def direct():
    """
    Get the regular expression pattern from the GET request (pattern), compile it
    and then use it to search the string within the 'text' in the GET request.
    """
    pattern = request.args.get("pattern", "")
    text = request.args.get("text", "")

    # Input Validation: Disallow metacharacters if possible.  If not, escape them.
    if re.search(r"[\.\*\+\?\{\}\(\)\[\]\^\$\|]", pattern):
        return "Error: Metacharacters are not allowed in the pattern.", 400

    # Alternative: If metacharacters *must* be allowed, escape them in the text:
    # text = re.escape(text)

    if not isinstance(text, str) or not isinstance(pattern, str):
        return "Error: Text and pattern must be strings.", 400

    if len(text) > 1000 or len(pattern) > 100:
        return "Error: Text and pattern lengths are limited.", 400

    try:
        # Compile the regular expression
        compiled_pattern = re.compile(pattern)

        # Search the text
        match = compiled_pattern.search(text)

        if match:
            result = f"Match found: {match.group(0)}"
        else:
            result = "No match found."

        return result, 200

    except re.error as e:
        return f"Error: Invalid regular expression: {e}", 400
    except Exception as e:
        return f"An unexpected error occurred: {e}", 500


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

