import os
from typing import Dict, Any
from urllib.parse import urlparse

from flask import Flask, request, Response, render_template_string, make_response, redirect
from markupsafe import escape

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for CSRF protection if using Flask-WTF

# Allowed domains for redirects (add your domain here)
ALLOWED_DOMAINS = ["example.com", "localhost"]

# Template for rendering.  Keep it simple and avoid complex logic here.
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Greeting</title>
</head>
<body>
    <h1>Hello, {{ name }}!</h1>
</body>
</html>
"""


def is_safe_domain(url: str) -> bool:
    """
    Checks if the given URL's domain is in the allowlist.
    """
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc in ALLOWED_DOMAINS
    except:
        return False


def render_response_from_env(env: Dict[str, Any]) -> Response:
    """
    Renders a response based on the 'name' parameter from the request and a template.
    """
    name = request.args.get("name", "World")

    # Input validation:  Strict allowlist for characters in 'name'.
    # This prevents XSS by only allowing alphanumeric characters and spaces.
    if not all(c.isalnum() or c.isspace() for c in name):
        name = "Invalid Input"  # Or handle the error more gracefully

    # Escape the name to prevent XSS.  Even with the allowlist, it's good practice.
    escaped_name = escape(name)

    try:
        # Render the template with the escaped name.
        rendered_template = render_template_string(TEMPLATE, name=escaped_name)

        # Create the response.
        response = make_response(rendered_template)

        # Set security headers.
        response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'"  # Very restrictive CSP

        # Set HttpOnly flag for cookies (if any are used).  Example:
        # response.set_cookie('sessionid', 'somevalue', httponly=True, secure=True) # Secure requires HTTPS

        return response
    except Exception as e:
        # Handle template rendering errors gracefully.  Log the error.
        print(f"Template rendering error: {e}")
        return Response("Internal Server Error", status=500)


@app.route("/")
def home():
    """
    Handles the home route and calls render_response_from_env.
    """
    return render_response_from_env(os.environ)


@app.route("/redirect")
def redirect_route():
    """
    Handles redirects, but only to allowed domains.
    """
    target_url = request.args.get("url")

    if target_url and is_safe_domain(target_url):
        return redirect(target_url)
    else:
        return "Invalid or unsafe redirect URL.", 400


if __name__ == "__main__":
    #  NEVER USE debug=True IN PRODUCTION!
    app.run(debug=False, host="0.0.0.0", port=5000)

