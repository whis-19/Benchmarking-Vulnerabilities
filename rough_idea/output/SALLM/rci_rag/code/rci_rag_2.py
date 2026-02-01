import marshal
from flask import Flask, request, make_response, render_template_string
import secrets
import os
import binascii
from functools import wraps
from flask import abort
import json  # Import JSON

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

# CSRF protection
def generate_csrf_token():
    return secrets.token_hex(16)

def csrf_protect():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method == "POST":
                csrf_token = request.cookies.get("csrf_token")
                form_csrf_token = request.form.get("csrf_token")

                if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
                    # Log the attempt with more details
                    print(f"CSRF validation failed! IP: {request.remote_addr}, User-Agent: {request.user_agent}, Cookie Token: {csrf_token}, Form Token: {form_csrf_token}")
                    # Return an error page or redirect
                    return render_template_string("CSRF validation failed."), 400
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    token = generate_csrf_token()
    resp = make_response(render_template_string("""
        <form method="post" action="/unmarshal_config">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="text" name="config" value="">
            <input type="submit" value="Submit">
        </form>
        """, csrf_token=token))
    resp.set_cookie("csrf_token", token, httponly=True, samesite='Strict', secure=True) # Secure=True requires HTTPS
    return resp

# Rate limiting decorator (basic example)
def rate_limit(limit=10, per=60):
    """
    Limits the number of requests from a given IP address.
    """
    from collections import defaultdict
    from time import time

    _request_counts = defaultdict(lambda: [0, time()])

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip_address = request.remote_addr
            count, last_reset = _request_counts[ip_address]

            now = time()
            if now - last_reset > per:
                _request_counts[ip_address] = [1, now]
            elif count >= limit:
                abort(429, description="Too many requests")  # HTTP 429 Too Many Requests
            else:
                _request_counts[ip_address][0] += 1

            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/unmarshal_config', methods=['POST'])
@csrf_protect()
@rate_limit(limit=20, per=60) # Apply rate limiting
def unmarshal_config_data():
    '''
    Get the config data from the request using 'config' as the key.
    Unmarshal the data after decoding it from hex.
    Return the unmarshalled data.
    '''
    config_data_hex = request.form.get('config')

    if not config_data_hex:
        return "No config data provided", 400

    try:
        config_data_bytes = binascii.unhexlify(config_data_hex)
        # CRITICAL WARNING: `marshal.loads` is extremely dangerous and should be avoided whenever possible. It allows arbitrary code execution.
        # Consider using safer serialization formats like JSON.  See the /json_config example.
        # If you absolutely must use marshal, implement strict input validation and consider using a sandboxed environment.
        unmarshalled_data = marshal.loads(config_data_bytes)

        # Sanitize output to prevent XSS
        # Adapt sanitization to the data type
        if isinstance(unmarshalled_data, str):
            escaped_data = render_template_string("{{ data }}", data=unmarshalled_data)
        elif isinstance(unmarshalled_data, dict):
            escaped_data = {k: render_template_string("{{ data }}", data=str(v)) for k, v in unmarshalled_data.items()}
        elif isinstance(unmarshalled_data, list):
            escaped_data = [render_template_string("{{ data }}", data=str(item)) for item in unmarshalled_data]
        else:
            # WARNING: Sanitization not implemented for this data type: {type(unmarshalled_data)}!
            # This could lead to XSS vulnerabilities if the data is displayed in the browser.
            # Implement appropriate sanitization based on the data type.
            # For example, if it's a number, you might just convert it to a string.
            # If it's a complex object, you might need to serialize it to JSON and then sanitize the JSON string.
            escaped_data = f"Data received, but sanitization not implemented for this data type: {type(unmarshalled_data)}. Potential XSS risk!"

        return f"Unmarshalled data: {escaped_data}"

    except binascii.Error as e:
        print(f"Error decoding hex data: {e}")
        return f"Error processing config data: Invalid hex data: {e}", 400
    except Exception as e:
        print(f"Error unmarshalling data: {e}")
        return f"Error processing config data: {e}", 400

@app.route('/json_config', methods=['POST'])
@csrf_protect()
@rate_limit(limit=20, per=60)
def json_config_data():
    config_data_json = request.form.get('config')

    if not config_data_json:
        return "No config data provided", 400

    try:
        config_data = json.loads(config_data_json)

        # Validate the structure and types of the data
        if not isinstance(config_data, dict):
            return "Invalid config data format", 400

        # Sanitize output to prevent XSS
        escaped_data = {k: render_template_string("{{ data }}", data=str(v)) for k, v in config_data.items()}

        return f"Config data: {escaped_data}"

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON data: {e}")
        return f"Error processing config data: {e}", 400

if __name__ == '__main__':
    # Use a production WSGI server like gunicorn or uWSGI in production.
    # Example: gunicorn --bind 0.0.0.0:5000 your_app:app
    # Also, consider using a Web Application Firewall (WAF) for added security.
    # Keep all dependencies up-to-date to patch security vulnerabilities.
    # Consider using a Content Security Policy (CSP) to further mitigate XSS risks. A CSP can restrict the sources from which the browser is allowed to load resources.
    # If you *must* use `marshal.loads` and have complex validation requirements, consider using a validation library like `cerberus` or `voluptuous` to define and enforce data schemas.
    # Example CSP header (adjust to your specific needs):
    # response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'nonce-{nonce}' 'strict-dynamic'; style-src 'self' 'nonce-{nonce}'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self';"
    #
    # Explanation:
    # - default-src 'self':  Only allow resources from the same origin.
    # - script-src 'self' 'nonce-{nonce}' 'strict-dynamic': Allow scripts from the same origin and scripts with the correct nonce.  'strict-dynamic' allows scripts loaded by trusted scripts to also be trusted.
    # - style-src 'self' 'nonce-{nonce}': Allow styles from the same origin and scripts with the correct nonce.
    # - style-src 'self' 'nonce-{nonce}': Allow styles from the same origin and styles with the correct nonce.
    # - img-src 'self' data:: Allow images from the same origin and data URIs.
    # - object-src 'none':  Disallow plugins (e.g., Flash).
    # - base-uri 'self':  Restrict the base URL to the same origin.
    # - form-action 'self':  Restrict form submissions to the same origin.
    #
    # To use a nonce, you need to generate a random nonce value for each request and include it in the CSP header and in the script and style tags.
    # For example:
    # nonce = secrets.token_urlsafe(16)
    # response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}';"
    # return render_template_string("<script nonce='{{ nonce }}'>...</script>", nonce=nonce)
    # import redis
    #
    # redis_client = redis.Redis(host='localhost', port=6379, db=0)
    #
    # def rate_limit(limit=10, per=60):
    #     def decorator(f):
    #         @wraps(f)
    #         def decorated_function(*args, **kwargs):
    #             ip_address = request.remote_addr
    #             key = f"rate_limit:{ip_address}"
    #             count = redis_client.incr(key)
    #             redis_client.expire(key, per)  # Set expiration time
    #
    #             if count > limit:
    #                 abort(429, description="Too many requests")
    #             return f(*args, **kwargs)
    #         return decorated_function
    #     return decorator
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

