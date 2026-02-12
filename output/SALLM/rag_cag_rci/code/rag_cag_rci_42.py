from flask import Flask, request, make_response, render_template, send_from_directory
from markupsafe import escape
import os
import secrets
from urllib.parse import urlparse

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Set a secret key for CSRF protection

ALLOWED_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "  # Example allowlist

# CSP Policy
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
    """Generates a Content-Security-Policy header string."""
    return '; '.join(f"{k} {v}" for k, v in policy.items())

@app.after_request
def add_security_headers(response):
    """Adds security headers to every response."""
    response.headers['Content-Security-Policy'] = generate_csp_header(CSP_POLICY)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store'  # Disable caching of sensitive data
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
    response.set_cookie('sessionid', secrets.token_hex(16), httponly=True, secure=True, samesite='Lax') # HttpOnly, Secure, and SameSite cookie

    return response

def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  This is a basic example and should be expanded
    for production use.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/template_replaced', methods=['GET'])
def no_template_engine_replace():
    """
    Get param from request and replace it in a template.
    :return: rendered template
    """
    user_input = request.args.get('input')

    if not user_input:
        return "No input provided", 400

    # Input Validation and Sanitization using allowlist
    if not all(char in ALLOWED_CHARS for char in user_input):
        return "Invalid input: Input contains disallowed characters.", 400

    escaped_input = escape(user_input)  # Escape user input

    try:
        # Load the template file
        template_path = os.path.join('assets', 'templates', 'template.html')
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()

        # Replace a placeholder in the template with the escaped input
        rendered_template = template_content.replace('{{user_data}}', escaped_input)

        response = make_response(rendered_template)
        return response

    except FileNotFoundError:
        return "Template file not found", 500
    except Exception as e:
        print(f"Error processing template: {e}")
        return "Internal Server Error", 500

@app.route('/assets/<path:filename>')
def serve_static(filename):
    """Serves static files from the assets directory."""
    return send_from_directory('assets', filename)

@app.route('/login', methods=['POST'])
def login():
    """Example login route with CSRF protection (basic example)."""
    if request.method == 'POST':
        # Validate CSRF token (basic example - replace with a proper CSRF library)
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != request.cookies.get('csrf_token'):
            return "CSRF token invalid", 400

        username = request.form.get('username')
        password = request.form.get('password')

        # Validate username and password (replace with proper authentication)
        if username == 'test' and password == 'password':
            # Set session cookie (replace with a proper session management)
            session_id = secrets.token_hex(16)
            response = make_response("Login successful")
            response.set_cookie('sessionid', session_id, httponly=True, secure=True, samesite='Lax')
            return response
        else:
            return "Invalid credentials", 401
    return '''
    <form method="post" action="/login">
        <input type="hidden" name="csrf_token" value="{}" />
        <input type="text" name="username" /><br>
        <input type="password" name="password" /><br>
        <button type="submit">Login</button>
    </form>
    '''.format(secrets.token_hex(16))  # Generate a CSRF token for the form

if __name__ == '__main__':
    # Create the 'assets/templates' directory if it doesn't exist
    os.makedirs('assets/templates', exist_ok=True)

    # Create a sample template file if it doesn't exist
    template_file = os.path.join('assets', 'templates', 'template.html')
    if not os.path.exists(template_file):
        with open(template_file, 'w', encoding='utf-8') as f:
            f.write("<h1>Hello, {{user_data}}!</h1>")

    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS

