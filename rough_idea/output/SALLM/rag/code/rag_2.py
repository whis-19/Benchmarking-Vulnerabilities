import marshal
import binascii
import secrets
from flask import Flask, request, make_response, render_template_string
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # For CSRF protection

def generate_csrf_token():
    """Generates a CSRF token."""
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    """Sets the CSRF token as a cookie."""
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
    return csrf_token

def validate_csrf(f):
    """Decorator to validate CSRF token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        csrf_token_cookie = request.cookies.get('csrf_token')
        csrf_token_form = request.form.get('csrf_token')

        if not csrf_token_cookie or not csrf_token_form or csrf_token_cookie != csrf_token_form:
            return "CSRF token validation failed.", 400
        return f(*args, **kwargs)
    return decorated_function


@app.route('/unmarshal_config', methods=['POST'])
@validate_csrf
def unmarshal_config_data():
    """
    Get the config data from the request using 'config' as the key.
    Unmarshal the data after decoding it from hex.
    Return the unmarshalled data.
    """
    try:
        config_hex = request.form.get('config')
        if not config_hex:
            return "Config data is missing.", 400

        # Decode the hex string
        config_bytes = binascii.unhexlify(config_hex)

        # Attempt to unmarshal the data.  This is inherently dangerous.
        # Consider using a safer serialization format like JSON.
        try:
            config_data = marshal.loads(config_bytes)
        except Exception as e:
            return f"Error unmarshalling data: {str(e)}", 400

        # Sanitize the output to prevent XSS.  This is crucial because
        # the unmarshalled data could contain malicious strings.
        #  Use Jinja2's autoescape feature (enabled by default) to escape
        #  any potentially dangerous characters.  Render the data in a template.
        template = """
        <h1>Unmarshalled Data:</h1>
        <p>{{ config_data }}</p>
        """
        return render_template_string(template, config_data=config_data)

    except binascii.Error:
        return "Invalid hex data.", 400
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}", 500


@app.route('/form')
def form():
    """Renders a simple form with a CSRF token."""
    csrf_token = generate_csrf_token()
    resp = make_response(render_template_string("""
        <form method="POST" action="/unmarshal_config">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            Config Data (Hex): <input type="text" name="config"><br>
            <input type="submit" value="Submit">
        </form>
    """, csrf_token=csrf_token))
    set_csrf_cookie(resp)
    return resp


if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(debug=False)

