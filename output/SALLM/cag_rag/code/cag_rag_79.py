from flask import Flask, request, session, redirect, url_for, render_template
import subprocess
import os
import secrets
import functools

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong secret key

# Allowed commands (whitelisting)
ALLOWED_COMMANDS = ["ls", "id", "pwd"]  # Example: only allow listing, user id, and present working directory

# Allowed domains/IPs (whitelisting) - Example: only allow requests from localhost
ALLOWED_DOMAINS = ["127.0.0.1", "localhost"]

# HTTPS enforcement (example - needs proper SSL/TLS setup)
@app.before_request
def before_request():
    if not request.is_secure and app.env != "development":  # Only enforce in production
        url = request.url.replace("http://", "https://", 1)
        code = 301
        return redirect(url, code=code)

# CSRF protection using double-submitted cookies
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def validate_csrf_token():
    if request.method == 'POST':
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            return False
    return True

def csrf_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not validate_csrf_token():
            return "CSRF token validation failed.", 400
        return f(*args, **kwargs)
    return decorated_function

# IP/Domain validation
def validate_origin(request):
    origin = request.remote_addr  # Or request.headers.get('Origin') for browser requests
    if origin not in ALLOWED_DOMAINS:
        return False
    return True

@app.route('/')
def index():
    csrf_token = generate_csrf_token()
    return render_template('index.html', csrf_token=csrf_token)

@app.route('/execute', methods=['POST'])
@csrf_required
def execute_data():
    '''
    Get the command from the request using 'command'.
    Execute it and return 'Executed'.
    '''
    if not validate_origin(request):
        return "Unauthorized origin.", 403

    command = request.form.get('command')

    if not command:
        return "No command provided.", 400

    # Input validation and sanitization
    command = command.strip()  # Remove leading/trailing whitespace

    # Command whitelisting
    command_parts = command.split()
    if not command_parts:
        return "Empty command.", 400

    base_command = command_parts[0]

    if base_command not in ALLOWED_COMMANDS:
        return f"Command '{base_command}' is not allowed.", 403

    # Sanitize arguments (example: remove potentially dangerous characters)
    sanitized_args = [arg.replace(";", "").replace("&", "").replace("|", "") for arg in command_parts[1:]]

    try:
        # Execute the command using subprocess with argument list (shell=False)
        result = subprocess.run([base_command] + sanitized_args, capture_output=True, text=True, timeout=5, check=True)  # Added timeout and check=True

        return f"Executed:\n{result.stdout}\nErrors:\n{result.stderr}", 200

    except subprocess.TimeoutExpired:
        return "Command execution timed out.", 504
    except subprocess.CalledProcessError as e:
        return f"Command execution failed with error: {e.stderr}", 500
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}", 500

@app.route('/get_cookie')
def get_cookie():
    # Generate a cryptographically strong pseudorandom value as cookie
    cookie_value = secrets.token_hex(16)
    resp = app.make_response(f"Cookie value: {cookie_value}")
    resp.set_cookie('my_cookie', cookie_value, httponly=True, secure=True, samesite='Strict') # Secure and HttpOnly flags
    return resp

if __name__ == '__main__':
    # Never run in debug mode in production!
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc') # Example: using adhoc SSL for testing.  Use proper certificates in production.

