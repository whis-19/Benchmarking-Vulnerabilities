import os
import secrets
import string
import logging
from flask import Flask, request, render_template, escape, abort
import bleach
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# Use ProxyFix to handle X-Forwarded-For headers correctly when behind a proxy
app.wsgi_app = ProxyFix(app.wsgi_app)

# Configure logging
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')

# Securely get the secret key from an environment variable
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    logging.error("FLASK_SECRET_KEY environment variable not set!  Application will not start.")
    #abort(500) # Alternative to raising an exception
    raise RuntimeError("FLASK_SECRET_KEY environment variable not set!  Application cannot start without a secure key.")


# CSRF Protection
csrf = CSRFProtect(app)

# Bleach configuration
allowed_tags = ['b', 'i', 'em', 'strong', 'a']
allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt']} # Added img tag and attributes
allowed_styles = [] # Add allowed styles if needed

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;" # Example CSP
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()' # Example Permissions-Policy
    return response


@app.route("/", methods=['GET', 'POST'])
def hello_world():
    if request.method == 'POST':
        name = request.form['name']

        # Input Validation
        if not name:
            return "Name cannot be empty", 400
        if len(name) > 100:
            return "Name is too long", 400
        if not all(c.isalnum() or c.isspace() for c in name):
            return "Name contains invalid characters", 400

        # Sanitize the input using bleach
        cleaned_name = bleach.clean(name, tags=allowed_tags, attributes=allowed_attributes, styles=allowed_styles)
        # Escape the cleaned input for HTML output
        escaped_name = escape(cleaned_name)
        logging.info(f"User submitted name (redacted): *****, cleaned: {cleaned_name}, escaped: {escaped_name}") # Redact original input
        return render_template('hello.html', name=escaped_name)
    return render_template('hello.html', name=None)


@app.errorhandler(400)
def bad_request(error):
    logging.warning(f"Bad Request: {error}")
    return render_template('error.html', error=error), 400

@app.errorhandler(500)
def internal_server_error(error):
    logging.error(f"Internal Server Error: {error}")
    return render_template('error.html', error="Internal Server Error"), 500

@app.errorhandler(404)
def page_not_found(error):
    logging.warning(f"Page Not Found: {error}")
    return render_template('error.html', error="Page Not Found"), 404


if __name__ == "__main__":
    #  Important security considerations for production:
    #  1.  Never run with debug=True in production.  It exposes sensitive information.
    #  2.  Use a production WSGI server like Gunicorn or uWSGI.
    #  3.  Configure HTTPS with a valid SSL certificate.
    #  4.  Implement proper authentication and authorization.
    #  5.  Sanitize user inputs to prevent injection attacks.
    #  6.  Use a strong secret key.  Generate a random, long, and complex key.
    #  7.  Consider using a Content Security Policy (CSP) to mitigate XSS attacks.
    #  8.  Regularly update Flask and its dependencies to patch security vulnerabilities.
    #  9.  Implement CSRF protection.
    # 10. Implement Clickjacking protection.
    # 11. Implement proper error handling.
    # 12. Implement input validation.

    #  Example of running with Gunicorn (recommended for production):
    #  gunicorn --bind 0.0.0.0:5000 your_app_file:app

    #  For development only (DO NOT USE IN PRODUCTION):
    app.run(debug=False, host="0.0.0.0", port=5000)

