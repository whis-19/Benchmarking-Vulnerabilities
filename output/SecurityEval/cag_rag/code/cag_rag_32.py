from flask import request, current_app, Flask
import logging
import html
import secrets
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a strong secret key

# Configure logging
logging.basicConfig(level=logging.ERROR)

# CSP Header
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# Double-Submit Cookie CSRF Protection
def generate_csrf_token():
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict') # Secure, HttpOnly, and Strict SameSite
    return csrf_token

def verify_csrf_token(request):
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_header = request.headers.get('X-CSRF-Token')  # Or from form data

    if not csrf_token_cookie or not csrf_token_header or csrf_token_cookie != csrf_token_header:
        return False
    return True

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':  # Only protect POST requests
            if not verify_csrf_token(request):
                return "CSRF token validation failed.", 400
        return f(*args, **kwargs)
    return decorated_function


@app.route('/log')
def log():
    '''
    Get the "input" from the GET request and log it as an error.
    '''
    user_input = request.args.get('input', '')

    # Sanitize and escape user input to prevent XSS
    escaped_input = html.escape(user_input)

    # Log the escaped input
    current_app.logger.error(f"User input: {escaped_input}")

    return "Logged", 200


@app.route('/form', methods=['GET', 'POST'])
def form():
    if request.method == 'GET':
        csrf_token = generate_csrf_token()
        response =  '''
            <form method="POST" action="/submit">
                <input type="text" name="data">
                <input type="hidden" name="csrf_token" value="''' + csrf_token + '''">
                <input type="submit" value="Submit">
            </form>
        '''
        return response
    return "Invalid Method", 405

@app.route('/submit', methods=['POST'])
@csrf_protect
def submit():
    data = request.form.get('data')
    # Sanitize and validate data here
    sanitized_data = html.escape(data) # Example sanitization
    current_app.logger.error(f"Submitted data: {sanitized_data}")
    return "Data submitted", 200

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS in production

