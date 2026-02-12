import os
from typing import Dict, Any
from urllib.parse import urlparse

from flask import Flask, request, Response, render_template_string, make_response, redirect, url_for
from markupsafe import escape

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for CSRF protection if using Flask-WTF

# Define allowed domains/IPs for redirects (if needed)
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Replace with your allowed domains

# Strict allowlist for the 'name' parameter.  Only allow alphanumeric characters and spaces.
ALLOWED_NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

def is_safe_redirect_url(target):
    """
    Checks if a redirect target is safe.  This is crucial to prevent open redirects.
    """
    try:
        url = urlparse(target)
        if url.netloc:  # Has a network location (domain)
            return url.netloc in ALLOWED_DOMAINS and url.scheme in ['http', 'https']
        return True  # Relative URL is considered safe
    except:
        return False  # Invalid URL is considered unsafe


def render_response_from_env(env: Dict[str, Any]) -> Response:
    """
    Renders a template with a name parameter from the request.  Escapes the name
    parameter to prevent XSS.
    """
    name = request.args.get("name", "")

    # Validate and sanitize the 'name' parameter using a strict allowlist.
    sanitized_name = "".join(c for c in name if c in ALLOWED_NAME_CHARS)
    escaped_name = escape(sanitized_name)  # Escape for XSS protection

    template = env.get("template", "<h1>Hello, {{ name }}!</h1>")  # Default template

    try:
        rendered_template = render_template_string(template, name=escaped_name)
    except Exception as e:
        # Handle template rendering errors gracefully.  Log the error.
        print(f"Template rendering error: {e}")
        rendered_template = "<h1>Error rendering template.</h1>"

    response = make_response(rendered_template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' # Prevent Clickjacking
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Mitigate XSS
    return response


@app.route("/")
def home():
    """
    Handles the home route and calls render_response_from_env.
    """
    env = {"template": "<h1>Welcome, {{ name }}!</h1>"}  # Example environment
    return render_response_from_env(env)


@app.route("/redirect")
def redirect_route():
    """
    Handles redirects, but only to safe URLs.
    """
    target = request.args.get("target")

    if target and is_safe_redirect_url(target):
        return redirect(target)
    else:
        return "Invalid or unsafe redirect target.", 400


@app.route("/set_cookie")
def set_cookie():
    """
    Sets a cookie with HttpOnly flag.
    """
    resp = make_response("Cookie set!")
    resp.set_cookie('my_cookie', 'my_value', httponly=True, secure=True, samesite='Lax') # Secure and SameSite
    return resp


@app.errorhandler(404)
def page_not_found(e):
    """Handles 404 errors."""
    return "Page not found", 404


@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 errors."""
    return "Internal server error", 500


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

