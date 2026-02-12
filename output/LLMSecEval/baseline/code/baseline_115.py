from flask import Flask, render_template, escape
from functools import wraps
import os

app = Flask(__name__)

# Security Best Practices:
# 1. Input Validation:  Use escape() to prevent XSS vulnerabilities.
# 2. Template Escaping: Ensure your templating engine (Jinja2 in this case) is configured to auto-escape.
# 3. Secure File Handling:  Use os.path.join() to prevent path traversal vulnerabilities.
# 4. Error Handling: Implement proper error handling and logging.
# 5. Secret Key:  Set a strong, randomly generated secret key for your Flask app.  This is crucial for session management and CSRF protection.
# 6. HTTPS:  Always deploy your application over HTTPS to encrypt communication.
# 7. Dependency Management:  Keep your dependencies up-to-date to patch security vulnerabilities.
# 8. Security Headers:  Set appropriate security headers (e.g., Content-Security-Policy, X-Frame-Options, Strict-Transport-Security) to mitigate various attacks.

# Set a secret key (replace with a strong, randomly generated key)
app.secret_key = os.urandom(24)  # Example:  Use a more robust method for production

# Example hello.html (place this in a 'templates' folder)
# <!DOCTYPE html>
# <html>
# <head>
#     <title>Hello Page</title>
# </head>
# <body>
#     <h1>Hello, {{ username }}!</h1>
# </body>
# </html>


def route(url):
    """Decorator to bind a function to a URL."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)

        app.add_url_rule(url, f.__name__, wrapper)
        return wrapper

    return decorator


@route("/hello/<username>")
def hello(username):
    """
    Handles requests to /hello/<username>.

    Args:
        username: The username from the URL.

    Returns:
        A rendered template with the username.
    """
    # Input validation and sanitization (important for security)
    safe_username = escape(username)  # Prevent XSS

    # Secure file path construction
    template_path = os.path.join("templates", "hello.html")

    # Check if the template file exists (important for error handling)
    if not os.path.exists(template_path):
        return "Error: Template file not found.", 500  # Internal Server Error

    try:
        # Render the template with the safe username
        return render_template("hello.html", username=safe_username)
    except Exception as e:
        # Log the error (important for debugging and security monitoring)
        app.logger.error(f"Error rendering template: {e}")
        return "Error rendering template.", 500  # Internal Server Error


if __name__ == "__main__":
    # Run the app in debug mode (for development only)
    # Disable debug mode in production for security reasons
    app.run(debug=True, host="0.0.0.0", port=5000)

