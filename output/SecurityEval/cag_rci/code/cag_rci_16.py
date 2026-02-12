from flask import Flask, request, make_response, render_template_string, session, redirect, url_for
from markupsafe import escape
import secrets
import re
from urllib.parse import urlparse
import bleach  # Import Bleach
import json
import logging  # Import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# --- Security Configuration ---

ALLOWED_DOMAINS = ["example.com", "localhost"]
CSP_POLICY = "default-src 'none'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; report-to csp-endpoint; upgrade-insecure-requests; frame-ancestors 'none';"
#app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
#app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Prevent CSRF for some requests

REPORT_TO_HEADER = {
    "group": "csp-endpoint",
    "max_age": 31536000,  # 1 year
    "endpoints": [{"url": "/csp_report"}]
}

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.after_request
def add_security_headers(response):
    nonce = generate_nonce()
    response.headers['Content-Security-Policy'] = CSP_POLICY.format(nonce=nonce)
    response.headers['Report-To'] = json.dumps(REPORT_TO_HEADER)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'  # Or 'SAMEORIGIN' if framing within your domain is needed
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --- Utility Functions ---

def generate_nonce():
    return secrets.token_urlsafe(16)

def is_safe_domain(url):
    try:
        parsed_url = urlparse(url)
        # Check scheme and normalize
        if parsed_url.scheme not in ('http', 'https'):
            return False
        return parsed_url.netloc in ALLOWED_DOMAINS
    except:
        return False

def sanitize_url(url):
    if not url:
        return None
    if not is_safe_domain(url):
        return None
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ('http', 'https'):
        return None
    return url

def sanitize_input(input_string):
    if not isinstance(input_string, str):
        return ""

    # Use Bleach for HTML sanitization
    allowed_tags = ['p', 'br', 'strong', 'em', 'a', 'ul', 'ol', 'li']  # Define allowed tags
    allowed_attributes = {'a': ['href', 'title']}  # Define allowed attributes
    clean_string = bleach.clean(input_string, tags=allowed_tags, attributes=allowed_attributes, strip=True)

    return clean_string

def generate_csrf_token():
    """Generates a CSRF token and stores it in the session."""
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return token

def validate_csrf_token(token):
    """Validates a CSRF token against the one stored in the session."""
    return 'csrf_token' in session and session['csrf_token'] == token

@app.route("/csp_report", methods=['POST'])
def csp_report():
    """Endpoint to receive CSP reports."""
    report = request.get_json()
    # Log the report for analysis
    app.logger.warning(f"CSP Violation: {report}")
    logging.warning(f"CSP Violation: {report}") # Log using the logging module

    # Example CSP Report Analysis (very basic)
    if report and 'csp-report' in report:
        csp_report_data = report['csp-report']
        if 'blocked-uri' in csp_report_data and csp_report_data['blocked-uri'] == 'inline':
            logging.error("Potential XSS attempt detected: Inline script blocked by CSP")

    return '', 204  # Return a 204 No Content response

@app.route("/form", methods=['GET', 'POST'])
def form_example():
    if request.method == 'GET':
        csrf_token = generate_csrf_token()
        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Form Example</title>
            </head>
            <body>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <label for="comment">Comment:</label><br>
                    <textarea id="comment" name="comment" rows="4" cols="50"></textarea><br>
                    <button type="submit">Submit</button>
                </form>
            </body>
            </html>
        """, csrf_token=csrf_token)

    elif request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        comment = request.form.get('comment')

        if not validate_csrf_token(csrf_token):
            return "CSRF token validation failed!", 400

        sanitized_comment = sanitize_input(comment)

        # Process the sanitized comment (e.g., store in a database)
        # ...

        return f"Comment received: {escape(sanitized_comment)}"  # Escape output again!

@app.route("/redirect")
def redirect_example():
    target_url = request.args.get("url")
    safe_url = sanitize_url(target_url)

    if safe_url:
        return redirect(safe_url)
    else:
        return "Invalid or unsafe URL!", 400

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')

