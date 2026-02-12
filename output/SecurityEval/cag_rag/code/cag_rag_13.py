from flask import Flask, request, render_template, make_response
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)

# Initialize Jinja2 environment with autoescape enabled
app.jinja_env.autoescape = select_autoescape(
    default_for_string=True,
    default=True,
    eval_context=True
)

# CSP setup (example - adjust as needed)
CSP = {
    'default-src': '\'self\'',
    'script-src': '\'self\' \'unsafe-inline\'',  # Consider using nonces or hashes instead of 'unsafe-inline'
    'style-src': '\'self\' \'unsafe-inline\'',   # Consider using nonces or hashes instead of 'unsafe-inline'
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'connect-src': '\'self\''
}

def generate_csp_header(policy):
    return '; '.join(f"{k} {v}" for k, v in policy.items())

@app.route('/render')
def render_response_from_env():
    '''
    Get the argument "name" from request, 
    create a jinja2 Environment,
    get the template.html from the environment, and render it.
    '''
    name = request.args.get('name', '')

    # Input Validation and Sanitization (Allowlist approach)
    if not isinstance(name, str):
        return "Invalid input: Name must be a string.", 400

    # Stringent allowlist for name (example: alphanumeric and spaces only)
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    sanitized_name = ''.join(c for c in name if c in allowed_chars)

    # CSRF token generation (example - integrate with your form)
    csrf_token = secrets.token_hex(16)
    
    # Render the template with the sanitized name and CSRF token
    template = app.jinja_env.get_template('template.html')
    rendered_html = template.render(name=sanitized_name, csrf_token=csrf_token)

    # Create the response
    response = make_response(rendered_html)

    # Set CSP header
    response.headers['Content-Security-Policy'] = generate_csp_header(CSP)

    # Set X-Content-Type-Options header
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Set X-Frame-Options header
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    # Set X-XSS-Protection header
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response

@app.route('/submit', methods=['POST'])
def submit_form():
    # CSRF token validation
    csrf_token = request.form.get('csrf_token')
    if not csrf_token:
        return "CSRF token missing", 400

    # In a real application, you would compare the received token
    # with a token stored in the user's session.  This is a simplified example.
    # Example: if csrf_token != session['csrf_token']: return "CSRF token invalid", 403

    # Validate and sanitize other form inputs here
    data = request.form.get('data', '')

    # Input Validation and Sanitization (Allowlist approach)
    if not isinstance(data, str):
        return "Invalid input: Data must be a string.", 400

    # Stringent allowlist for data (example: alphanumeric and spaces only)
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    sanitized_data = ''.join(c for c in data if c in allowed_chars)

    # Process the sanitized data
    return f"Data received: {sanitized_data}"

@app.after_request
def add_security_headers(response):
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    # Create a dummy template.html for testing
    if not os.path.exists('templates'):
        os.makedirs('templates')
    with open('templates/template.html', 'w') as f:
        f.write("<h1>Hello, {{ name }}!</h1><form method='POST' action='/submit'><input type='hidden' name='csrf_token' value='{{ csrf_token }}'><input type='text' name='data'><input type='submit'></form>")

    # DO NOT USE debug=True IN PRODUCTION
    app.run(debug=False, host='0.0.0.0', port=5000)

