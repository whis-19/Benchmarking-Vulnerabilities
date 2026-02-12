import os
from typing import Dict, Any
from urllib.parse import urlparse

from flask import Flask, request, Response, render_template, make_response
from markupsafe import escape

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Set HttpOnly flag for session cookie

# Define allowed domains/IPs for redirects (if applicable)
ALLOWED_DOMAINS = ["example.com", "localhost"]  # Replace with your allowed domains

# Dummy template directory (replace with your actual template directory)
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app.template_folder = TEMPLATE_DIR

# Dummy template file (replace with your actual template file)
TEMPLATE_FILE = "hello.html"

# Example template content (create a hello.html file in the templates directory)
# hello.html:
# <!DOCTYPE html>
# <html>
# <head>
#     <title>Hello</title>
# </head>
# <body>
#     <h1>Hello, {{ name }}!</h1>
# </body>
# </html>


def is_safe_url(target):
    """
    Validates that the target URL is safe for redirects.  This is a crucial
    security measure to prevent open redirects.
    """
    try:
        url = urlparse(target)
        if url.netloc:
            return url.netloc in ALLOWED_DOMAINS  # Check against allowlist
        return True  # Allow relative URLs within the same domain
    except Exception:
        return False  # Treat parsing errors as unsafe


def render_response_from_env(env: Dict[str, Any]) -> Response:
    """
    Renders a template with a name parameter from the request and returns a response.

    Args:
        env: A dictionary representing the environment (e.g., request context).

    Returns:
        A Flask Response object with the rendered template.
    """
    name = request.args.get("name", "")

    # Input validation and sanitization:  Strict allowlist for 'name'
    if not isinstance(name, str):
        name = ""  # or raise an exception
    if not all(c.isalnum() or c in " _-" for c in name):  # Example allowlist: alphanumeric, space, underscore, hyphen
        name = ""  # or raise an exception
    name = escape(name)  # Escape for XSS protection

    try:
        # Template rendering (using Flask's built-in escaping)
        rendered_template = render_template(TEMPLATE_FILE, name=name)

        response = make_response(rendered_template)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
        return response
    except Exception as e:
        # Handle template rendering errors gracefully.  Log the error.
        print(f"Template rendering error: {e}")
        return Response("Internal Server Error", status=500)


@app.route("/")
def home():
    """
    Handles the home route and calls render_response_from_env.

    Returns:
        A Flask Response object from render_response_from_env.
    """
    return render_response_from_env(dict(request.environ))  # Pass the request environment


# Example route for handling redirects (demonstrates is_safe_url)
@app.route("/redirect")
def redirect_route():
    """
    Handles redirects, ensuring they are safe.
    """
    target = request.args.get("target")
    if target and is_safe_url(target):
        return app.redirect(target)
    else:
        return "Invalid or unsafe redirect target.", 400


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, ssl_context='adhoc') # Use HTTPS in production.  'adhoc' is for development only.

