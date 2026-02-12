import logging
import secrets
from flask import Flask, request, make_response, render_template_string
from urllib.parse import urlparse

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # For CSRF protection

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed domains/IPs (example)
ALLOWED_DOMAINS = ['example.com', '127.0.0.1']  # Add your allowed domains

# CSRF protection using double-submitted cookies
def generate_csrf_token():
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure, HttpOnly, and Strict SameSite
    return csrf_token

def verify_csrf_token(request):
    cookie_csrf_token = request.cookies.get('csrf_token')
    form_csrf_token = request.form.get('csrf_token')  # Assuming CSRF token is submitted in a form

    if not cookie_csrf_token or not form_csrf_token or cookie_csrf_token != form_csrf_token:
        logging.warning("CSRF token validation failed.")
        return False
    return True

def is_valid_url(url):
    """
    Validates a URL against a whitelist of allowed domains.
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False

        if result.netloc not in ALLOWED_DOMAINS:
            logging.warning(f"URL {url} blocked due to domain not in allowlist.")
            return False

        return True
    except:
        return False

@app.route('/log', methods=['GET', 'POST'])  # Use POST for state changes, but this example logs data
def log():
    """
    Logs data from request and returns it.  Includes CSRF protection and input validation.
    """
    if request.method == 'POST':
        if not verify_csrf_token(request):
            return "CSRF token validation failed.", 400

        data_to_log = request.form.get('data')  # Get data from the form

        # Input validation and sanitization (example)
        if data_to_log:
            # Basic sanitization - replace potentially harmful characters
            data_to_log = data_to_log.replace("<", "&lt;").replace(">", "&gt;")

            # Validate URL if present
            if "url" in request.form:
                url = request.form.get("url")
                if not is_valid_url(url):
                    return "Invalid URL provided.", 400

            logging.info(f"Received data: {data_to_log}")
            return f"Logged: {data_to_log}"
        else:
            return "No data provided.", 400

    else:  # GET request - serve the form with CSRF protection
        response = make_response(render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Log Data</title>
            </head>
            <body>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <label for="data">Enter data to log:</label><br>
                    <input type="text" id="data" name="data"><br><br>
                    <label for="url">Enter URL (optional):</label><br>
                    <input type="text" id="url" name="url"><br><br>
                    <input type="submit" value="Submit">
                </form>
            </body>
            </html>
        """, csrf_token=set_csrf_cookie(response))) # Set CSRF cookie on GET
        response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
        return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Enforce HTTPS (example using adhoc certificate)

