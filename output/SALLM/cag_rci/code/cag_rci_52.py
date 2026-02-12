# Example of adding a timestamp to the CSRF token
import time

def generate_csrf_token():
    """Generates a CSRF token and stores it in the session with a timestamp."""
    token = secrets.token_hex(16)
    session['csrf_token'] = {'token': token, 'timestamp': time.time()}
    return token

def validate_csrf_token(token):
    """Validates the CSRF token against the one stored in the session."""
    if 'csrf_token' not in session:
        return False

    csrf_data = session['csrf_token']
    if csrf_data['token'] != token:
        return False

    # Check if the token is too old (e.g., 15 minutes)
    if time.time() - csrf_data['timestamp'] > 900:  # 900 seconds = 15 minutes
        return False

    return True

# Example of checking for embedded credentials in URLs
def is_valid_url(url):
    try:
        result = urlparse(url)
        if not result.scheme or result.scheme not in ['http', 'https']:
            return False

        if not result.netloc:
            return False

        # Check for embedded credentials
        if "@" in result.netloc and result.netloc.split("@")[0] != result.netloc:
            return False

        domain = result.netloc
        if domain.startswith("www."):
            domain = domain[4:]

        if domain not in ALLOWED_DOMAINS:
            return False

        # Prevent relative URLs and dangerous schemes
        if url.startswith("//") or url.startswith("/") or url.startswith("./") or url.startswith("../"):
            return False
        if result.scheme == "javascript" or result.scheme == "data":
            return False

        return True
    except:
        return False

# Example of logging errors in the error handlers
import logging

logging.basicConfig(level=logging.ERROR)  # Configure logging

@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 Internal Server Error errors."""
    logging.exception("Internal Server Error")  # Log the exception
    return render_template('error.html', error="Internal Server Error"), 500

# Example of using a nonce in the CSP header (index.html)
# <!DOCTYPE html>
# <html>
# <head>
#     <title>Secure Search</title>
#     <style>
#         body { font-family: sans-serif; }
#         .error { color: red; }
#         .result { margin-top: 10px; }
#     </style>
#     <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'nonce-{{ nonce }}'; style-src 'self' 'nonce-{{ nonce }}'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'">
# </head>
# <body>
#     <h1>Secure Search</h1>
#     {% if error %}
#         <p class="error">{{ error }}</p>
#     {% endif %}
#     <form action="/search" method="post">
#         <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
#         <label for="user_input">Enter text:</label>
#         <input type="text" id="user_input" name="user_input">
#         <button type="submit">Search</button>
#     </form>
#
#     <form action="/url_check" method="post">
#         <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
#         <label for="url">Enter URL:</label>
#         <input type="text" id="url" name="url">
#         <button type="submit">Check URL</button>
#     </form>
#
#     {% if result is not none %}
#         <div class="result">
#             Search Result: {{ result }}
#         </div>
#     {% endif %}
#
#     {% if input %}
#         <div class="result">
#             You entered: {{ input }}
#         </div>
#     {% endif %}
#
#     {% if url_result %}
#         <div class="result">
#             Sanitized URL: {{ escaped_url }}
#         </div>
#     {% endif %}
# </body>
# </html>

# In your Flask route:
import uuid

@app.route('/')
def index():
    """Renders the main page with a CSRF token and nonce."""
    csrf_token = generate_csrf_token()
    nonce = uuid.uuid4().hex  # Generate a unique nonce
    return render_template('index.html', csrf_token=csrf_token, nonce=nonce)

