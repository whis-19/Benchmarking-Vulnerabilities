import re
from flask import Flask, request, Response, session
import os
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import Markup  # For output encoding
import bleach # For sanitization (if needed)
import unicodedata # For Unicode normalization

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a strong secret key

# Ensure debugging is disabled in production
app.debug = False

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Session Management - Use a secure session store in production (e.g., Redis, Memcached)
# The default Flask session store is not suitable for production.
# Example (requires installing redis):
# from flask_session import Session
# app.config['SESSION_TYPE'] = 'redis'
# app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379)
# Session(app)


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Example CSP - adjust to your application's needs!  Avoid 'unsafe-inline' if possible.
    # Consider using nonces or hashes for inline scripts and styles for better security.
    nonce = session.get('csp_nonce', '')
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self' data:;"
    return response

@app.route('/filter_script_tags', methods=['POST'])
@limiter.limit("5/minute")  # Rate limit this endpoint
def filterScriptTags():
    """
    Get content from the request using 'content' and remove script tags from it.
    """
    if request.method == 'POST':
        content = request.form.get('content', '')

        # Input Validation vs. Sanitization:
        # This code uses input validation (allowlist).  Sanitization attempts to clean potentially malicious input,
        # while validation ensures that the input conforms to the expected format and constraints.
        # Validation is generally preferred as it's more predictable and less prone to bypasses.

        # Input length limit to prevent DoS
        if len(content) > 1000:  # Example limit
            return Response("Input too long.", status=400)

        # Normalize Unicode characters
        content = unicodedata.normalize('NFKC', content)

        # Validate the input:  Allowlist approach.  Only allow alphanumeric, spaces, and some punctuation.
        if not re.match(r"^[a-zA-Z0-9\s.,?!():;'\"]*$", content):
            return Response("Invalid input. Only alphanumeric characters, spaces, and common punctuation are allowed.", status=400)

        # Remove script tags using a safer approach (more restrictive regex)
        # This regex is designed to be more resistant to bypasses.  However, consider using a proper HTML parser and sanitizer like bleach.
        # clean_content = re.sub(r'<script\b[^>]*>.*?</script\b[^>]*>', '', content, flags=re.IGNORECASE)

        # Example using bleach for sanitization (if needed)
        allowed_tags = ['p', 'br', 'strong', 'em']  # Define allowed HTML tags
        allowed_attributes = {}  # No attributes allowed in this example
        allowed_styles = [] # No styles allowed

        clean_content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes, styles=allowed_styles, strip=True)


        # Double-submitted cookie defense
        csrf_token = request.cookies.get('csrf_token')
        form_csrf_token = request.form.get('csrf_token')

        if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
            return Response("CSRF token mismatch.", status=400)

        # Set HttpOnly flag for session cookie (if using sessions)
        session.permanent = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS

        return Response(f"Cleaned content: {Markup.escape(clean_content)}")
    else:
        return Response("Method not allowed. Use POST.", status=405)

@app.route('/form')
def form():
    """
    Serves a simple form with CSRF protection.
    """
    csrf_token = secrets.token_hex(16)
    session['csrf_token'] = csrf_token
    nonce = secrets.token_hex(16)  # Generate a nonce
    session['csp_nonce'] = nonce

    resp = Response(f"""
        <form action="/filter_script_tags" method="post">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            Content: <input type="text" name="content"><br>
            <input type="submit" value="Submit">
        </form>
        <script nonce="{nonce}">
            // Your inline script here
        </script>
    """)
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict') # Secure only if HTTPS, SameSite attribute
    return resp

if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

