from flask import request, Flask, make_response, redirect, url_for
import re
import html
import os
from urllib.parse import quote, urljoin
import secrets
import logging

app = Flask(__name__)
app.logger.setLevel(logging.INFO)  # Configure logging

# Rate limiting (example - adjust as needed)
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
    """Applies rate limiting before each request."""
    ip_address = request.remote_addr
    if is_rate_limited(ip_address):
        return "Rate limit exceeded. Please try again later.  Consider using a more robust rate limiting solution like Flask-Limiter for production environments.  Note: This basic implementation is vulnerable to IP address spoofing.  Consider authentication or other identifying factors.", 429

@app.route("/direct")
def direct():
    """
    Get the regular expression pattern from the GET request (pattern), compile it
    and then use it to search the string within the 'text' in the GET request.
    """
    pattern = request.args.get("pattern", "", type=str)
    text = request.args.get("text", "", type=str)

    # Input Validation and Sanitization
    if not pattern or not text:
        return "Error: Both 'pattern' and 'text' parameters are required.", 400

    # Option 1: Disallow Meta-characters (Recommended - Most Secure)
    if any(c in pattern for c in r".*+?()[]{}|\^$"):
        return "Error: Meta-characters are not allowed in the pattern. This is the *most secure* option to prevent regex injection. Allowing meta-characters can lead to ReDoS or other vulnerabilities.", 400

    # Option 2: Escape Meta-characters (Use with EXTREME CAUTION - NOT RECOMMENDED)
    # pattern = re.escape(pattern)  #  Use this ONLY if you want to treat the input as a literal string and understand the implications.  This is NOT a general solution for regex injection.

    # Option 3:  Strict Allowlist (Use with CAUTION - Must be VERY restrictive)
    # Example: Allow only alphanumeric characters and underscores
    # if not re.match(r"^[a-zA-Z0-9_]+$", pattern):
    #     return "Error: Invalid pattern format. Only alphanumeric characters and underscores are allowed.  Ensure the allowlist is extremely restrictive to prevent unexpected behavior. Even seemingly harmless characters like '.' can be dangerous if not carefully considered.", 400

    # Encoding and Response Headers
    response = make_response()
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    try:
        # Compile and Search (Only if validation passes)
        # Example of a vulnerable regex pattern for ReDoS: (a+)+$
        regex = re.compile(pattern)
        match = regex.search(text)

        if match:
            result = html.escape(match.group(0))  # Escape for safe HTML output
            response.data = f"Match found: {result}".encode('utf-8')
        else:
            response.data = "No match found.".encode('utf-8')

    except re.error as e:
        app.logger.error(f"Regex error: {e}. Pattern: {pattern}. Text: {text}") # Log the error
        response.data = f"Error: Invalid regular expression: {html.escape(str(e))}".encode('utf-8')
        response.status_code = 400

    # Session Cookie (Example - adjust as needed)
    response.set_cookie('session_id', secrets.token_hex(24), httponly=True, secure=True, samesite='Lax') # Secure and HttpOnly

    return response

# Example of redirect with validation
@app.route("/redirect_example")
def redirect_example():
    target = request.args.get("target", "")

    # Validate the target URL (very important!)
    if not target.startswith("https://example.com"):  # Replace with your allowed domain(s)
        return "Error: Invalid redirect target.  Must be HTTPS and within the allowed domain.", 400

    # Properly encode the URL.  Consider urljoin for relative paths, but quote is sufficient here.
    # encoded_target = quote(target, safe=":/")
    # target_url = urljoin(request.url_root, target) # Safer for relative paths, but not needed here due to validation
    encoded_target = quote(target, safe=":/")

    return redirect(encoded_target, code=302)  # Use 302 for temporary redirect

@app.route("/csp_example")
def csp_example():
    """Example of setting Content Security Policy (CSP) headers."""
    response = make_response("<h1>CSP Example</h1><script>alert('Hello from CSP!');</script>")
    # Example CSP directives:
    # 1. Restrict all resources to the same origin:
    # response.headers['Content-Security-Policy'] = "default-src 'self'"
    # 2. Allow scripts from the same origin and a trusted CDN:
    response.headers['Content-Security-Policy'] = "script-src 'self' https://trusted.cdn.com; object-src 'none'"
    return response

@app.route("/csp_example_nonce")
def csp_example_nonce():
    nonce = secrets.token_urlsafe(16)
    response = make_response(f"<h1>CSP Example with Nonce</h1><script nonce='{nonce}'>alert('Hello from CSP with Nonce!');</script>")
    response.headers['Content-Security-Policy'] = f"script-src 'self' 'nonce-{nonce}'; object-src 'none'; report-uri /csp_report"  # Add report-uri
    return response

@app.route("/csp_report", methods=['POST'])
def csp_report():
    # Handle CSP reports here (e.g., log them)
    app.logger.warning(f"CSP Violation Report: {request.get_json()}") # Log CSP reports
    return '', 204  # No Content

@app.route("/redirect_https_only")
def redirect_https_only():
    target = request.args.get("target", "")

    if not target.startswith("https://"):
        return "Error: Invalid redirect target. Must start with https://", 400

    encoded_target = quote(target, safe=":/")
    return redirect(encoded_target, code=302)

if __name__ == "__main__":
    # Disable debug mode in production!
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

