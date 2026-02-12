from flask import Flask, request, make_response, render_template_string
from jinja2 import Environment, FileSystemLoader
import re
import os

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

# Initialize Jinja2 environment with autoescape enabled (default, but explicit for emphasis)
loader = FileSystemLoader(searchpath="templates/")
env = Environment(loader=loader, autoescape=True)


@app.route('/')
def render_template():
    """
    Get name from the request using 'name'.
    Render the template with the name from the jinja2 template.
    :return: The rendered template.
    """
    name = request.args.get('name', '')

    # Input validation:  Strict allowlist for 'name'
    if not re.match(r"^[a-zA-Z0-9\s]*$", name):
        return "Invalid name. Only alphanumeric characters and spaces are allowed.", 400

    #  Template rendering using Jinja2 with autoescaping
    try:
        template = env.get_template('index.html')  # Assuming index.html exists in templates/
        rendered_template = template.render(name=name)

        response = make_response(rendered_template)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
        response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
        response.headers['X-Frame-Options'] = 'SAMEORIGIN' # Prevent clickjacking
        response.headers['Content-Security-Policy'] = "default-src 'self'" # Prevent XSS
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin' # Control referrer information
        response.headers['Permissions-Policy'] = 'geolocation=()' # Disable geolocation

        # Set HttpOnly flag for session cookie (if sessions are used)
        # Example (if you're using Flask-Session or similar):
        # session.permanent = True
        # app.config['SESSION_COOKIE_HTTPONLY'] = True
        # app.config['SESSION_COOKIE_SECURE'] = True # Only if using HTTPS

        return response

    except Exception as e:
        # Handle template errors gracefully.  Log the error.
        print(f"Template error: {e}")  # Log the error (use a proper logging mechanism in production)
        return "An error occurred while rendering the template.", 500


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=()'
    return response


if __name__ == '__main__':
    #  Do not use debug=True in production!
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

