from flask import Flask, request, render_template, make_response
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import secrets
from urllib.parse import urlparse

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Required for CSRF protection

# Initialize Jinja2 environment with autoescape enabled
app.jinja_env.autoescape = select_autoescape(
    default=True,
    values=('html', 'xml'),
    default_for_string=True,
)

# CSP Header
CSP_POLICY = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'frame-ancestors': '\'none\'',
    'base-uri': '\'none\'',
    'form-action': '\'self\'',
}

def generate_csp_header(policy):
    return '; '.join(f"{k} {v}" for k, v in policy.items())

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = generate_csp_header(CSP_POLICY)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

def generate_csrf_token():
    return secrets.token_hex(16)

@app.route('/render', methods=['GET', 'POST'])
def render_response_from_env():
    """
    Get the argument "name" from request,
    create a jinja2 Environment,
    get the template.html from the environment, and render it.
    """
    if request.method == 'POST':
        # CSRF validation
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != request.cookies.get('csrf_token'):
            return "CSRF token validation failed.", 400

        name = request.form.get('name')

        # Input validation and sanitization (string allowlist)
        if not name:
            name = "Guest"
        if not isinstance(name, str):
            return "Invalid name format.", 400

        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
        sanitized_name = ''.join(c for c in name if c in allowed_chars)

        # Render the template with the sanitized name
        template = app.jinja_env.get_template('template.html')
        rendered_html = template.render(name=sanitized_name)

        response = make_response(rendered_html)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response

    else:  # GET request
        csrf_token = generate_csrf_token()
        template = app.jinja_env.get_template('form.html')
        rendered_html = template.render(csrf_token=csrf_token)

        response = make_response(rendered_html)
        response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response

@app.route('/redirect')
def redirect_url():
    target = request.args.get('target')

    if not target:
        return "No target URL provided", 400

    # Validate URL using urllib.parse and an allowlist
    try:
        result = urlparse(target)
        if not all([result.scheme, result.netloc, result.path]):
            return "Invalid URL format", 400

        allowed_domains = ['example.com', 'safe-domain.net']  # Replace with your allowed domains
        if result.netloc not in allowed_domains:
            return "Disallowed domain", 400

        # Construct the full URL
        validated_url = result.geturl()

        # Redirect (use 302 Found for temporary redirect)
        return redirect(validated_url, code=302)

    except Exception as e:
        return f"Invalid URL: {e}", 400

from flask import redirect

if __name__ == '__main__':
    # Create dummy templates for demonstration
    template_dir = os.path.join(app.root_path, 'templates')
    os.makedirs(template_dir, exist_ok=True)

    with open(os.path.join(template_dir, 'template.html'), 'w') as f:
        f.write("<h1>Hello, {{ name }}!</h1>")

    with open(os.path.join(template_dir, 'form.html'), 'w') as f:
        f.write("""
        <form method="post" action="/render">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label for="name">Enter your name:</label>
            <input type="text" id="name" name="name"><br><br>
            <input type="submit" value="Submit">
        </form>
        """)

    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS

