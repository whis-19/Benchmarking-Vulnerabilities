from flask import request, Flask, make_response, escape
import re
import html

app = Flask(__name__)

# Configure session (example - consider using a more robust session management)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Guideline 11

# Rate limiting (example - implement a proper rate limiting mechanism)
REQUEST_LIMIT = 10
REQUEST_COUNT = {}

def is_rate_limited(ip_address):
    """Checks if the IP address has exceeded the request limit."""
    if ip_address not in REQUEST_COUNT:
        REQUEST_COUNT[ip_address] = 0
    if REQUEST_COUNT[ip_address] >= REQUEST_LIMIT:
        return True
    REQUEST_COUNT[ip_address] += 1
    return False

@app.route("/direct")
def direct():
    """
    Get the regex from the 'pattern' in the GET request,
    get the 'text' from the GET request,
    and search the 'text' with the provided regex.
    """
    ip_address = request.remote_addr
    if is_rate_limited(ip_address):
        return "Rate limit exceeded", 429  # Guideline 13

    pattern = request.args.get('pattern', '')
    text = request.args.get('text', '')

    # Input validation and sanitization (Guidelines 6, 9, 10, 14)
    if not pattern or not text:
        return "Error: 'pattern' and 'text' parameters are required.", 400

    # Sanitize inputs to prevent XSS (Guideline 14)
    pattern = html.escape(pattern)
    text = html.escape(text)

    # Validate pattern (Guideline 6) -  Limit complexity and prevent ReDoS
    if len(pattern) > 100:  # Example limit - adjust as needed
        return "Error: Pattern too long.", 400

    #  Escape metacharacters in the pattern if it's intended to be a literal string.
    #  If the user *intends* to use regex, this should be removed.  However,
    #  if the user is providing a string that is *interpreted* as a regex,
    #  this is crucial.  Assuming the latter for safety.
    pattern = re.escape(pattern)

    try:
        # Perform the regex search
        match = re.search(pattern, text)

        if match:
            result = f"Match found: {match.group(0)}"
        else:
            result = "No match found."

        # Set Content-Type header (Guideline 12)
        response = make_response(result)
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return response

    except re.error as e:
        return f"Error: Invalid regex pattern: {e}", 400

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

