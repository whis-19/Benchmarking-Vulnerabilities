import os
from typing import Dict, Any
from urllib.parse import urlparse

from flask import Flask, request, Response, render_template, make_response
from markupsafe import escape

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for CSRF protection if using Flask-WTF

ALLOWED_DOMAINS = ["example.com", "localhost"]  # Example allowlist

def is_valid_url(url: str) -> bool:
    """
    Validates a URL against an allowlist of domains.  Also checks for a valid scheme (HTTPS).
    """
    try:
        result = urlparse(url)
        return result.netloc in ALLOWED_DOMAINS and result.scheme == "https"  # Enforce HTTPS
    except:
        return False

def render_response_from_env(env: Dict[str, Any]) -> Response:
    """
    Renders a template with a name parameter from the request, escaping the name for XSS protection.
    """
    name = request.args.get("name", "World")  # Default to "World" if no name is provided

    # Sanitize the name parameter to prevent XSS.  Use escape from markupsafe.
    sanitized_name = escape(name)

    template = env.get("template", "<h1>Hello, {}!</h1>")  # Default template

    try:
        rendered_template = render_template(template_string=template, name=sanitized_name)
    except Exception as e:
        # Handle template rendering errors gracefully.  Log the error.
        print(f"Template rendering error: {e}")
        rendered_template = "<h1>Error rendering template.</h1>"  # Provide a safe fallback

    response = make_response(rendered_template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' # Prevent clickjacking
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Mitigate XSS
    return response


@app.route("/")
def home():
    """
    Calls render_response_from_env with a predefined environment.
    """
    env = {"template": "<h1>Hello, {{ name }}!</h1>"}
    return render_response_from_env(env)


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response


# Example route demonstrating URL validation
@app.route("/redirect")
def redirect_url():
    """
    Demonstrates URL validation before redirecting.  This is just an example;
    actual redirects should be handled with extreme care.
    """
    target_url = request.args.get("url")

    if target_url and is_valid_url(target_url):
        # In a real application, you would likely use a safer redirect mechanism
        # and log the redirect.  This is just an example.
        return f"Redirecting to: {target_url}" # Replace with a safe redirect
    else:
        return "Invalid URL or domain.", 400


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

