from flask import Flask, render_template, escape
from functools import wraps
import os

app = Flask(__name__)

# Security Best Practices:
# 1. Input Validation and Sanitization:  Use escape() to prevent XSS.
# 2. Template Engine Security:  Flask's Jinja2 is generally safe, but avoid using `safe` filter unless absolutely necessary and you trust the source.
# 3.  Secret Key:  Crucial for session management and CSRF protection.  Generate a strong, random key and store it securely (environment variable is a good option).
# 4.  Error Handling:  Avoid leaking sensitive information in error messages.
# 5.  HTTPS:  Always use HTTPS to encrypt communication between the client and server.
# 6.  Content Security Policy (CSP):  Implement CSP to mitigate XSS attacks.
# 7.  Regular Security Audits:  Periodically review your code for vulnerabilities.

# Set a secret key for session management and CSRF protection.
#  Important:  Replace with a strong, randomly generated key.  Do *not* hardcode it in your source code.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_default_secret_key')  # Use environment variable

# Example of a more robust secret key generation (if you don't have one already)
# import secrets
# app.secret_key = secrets.token_hex(32)


# Custom decorator (optional, but demonstrates good practice)
def route(rule, **options):
    """Decorator to bind a function to a URL."""
    def decorator(f):
        @app.route(rule, **options)
        @wraps(f)  # Preserve function metadata
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.route('/hello/<username>')
def hello(username):
    """
    Greets the user by name.  Demonstrates input sanitization.
    """
    # Sanitize the username to prevent XSS attacks.
    safe_username = escape(username)

    # Render the template with the sanitized username.
    return render_template('hello.html', username=safe_username)


# Example of using the custom route decorator (equivalent to @app.route)
# @route('/greet/<name>')
# def greet(name):
#     return f"Hello, {escape(name)}!"


if __name__ == '__main__':
    #  Do not use debug=True in production!  It can expose sensitive information.
    app.run(debug=True)  # For development only.  Use a production WSGI server (e.g., gunicorn, uWSGI) in production.

