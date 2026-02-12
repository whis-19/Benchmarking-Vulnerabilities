from flask import Flask, request, make_response, render_template_string
import yaml
import secrets
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong secret key

# CSRF protection using a nonce
def generate_nonce():
    return secrets.token_hex(16)

def set_nonce_cookie(response):
    nonce = generate_nonce()
    response.set_cookie('csrf_nonce', nonce, httponly=True, secure=True, samesite='Strict')  # Secure cookie
    return nonce

def validate_nonce(request):
    form_nonce = request.form.get('csrf_nonce')
    cookie_nonce = request.cookies.get('csrf_nonce')

    if not form_nonce or not cookie_nonce or form_nonce != cookie_nonce:
        return False
    return True

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            if not validate_nonce(request):
                return "CSRF attack detected!", 400
        return f(*args, **kwargs)
    return decorated_function

@app.route('/form', methods=['GET'])
def form():
    """
    Serves a simple form with CSRF protection.
    """
    response = make_response(render_template_string('''
        <form method="post" action="/yaml">
            <input type="hidden" name="csrf_nonce" value="{{ csrf_nonce }}">
            <textarea name="yaml_data"></textarea>
            <button type="submit">Submit</button>
        </form>
    ''', csrf_nonce=generate_nonce()))
    set_nonce_cookie(response)
    return response

@app.route('/yaml', methods=['POST'])
@csrf_protect
def yaml_load():
    """
    Safely parses YAML data from the request and returns it.
    """
    yaml_data = request.form.get('yaml_data')

    if not yaml_data:
        return "No YAML data provided.", 400

    try:
        # Use yaml.safe_load to prevent arbitrary code execution
        data = yaml.safe_load(yaml_data)
        return str(data), 200  # Return the parsed data as a string
    except yaml.YAMLError as e:
        return f"Error parsing YAML: {str(e)}", 400
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), ssl_context='adhoc') # Enable HTTPS

