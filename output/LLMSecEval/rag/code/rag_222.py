from flask import Flask, request, make_response, escape
import secrets
import re
import html

app = Flask(__name__)

# Regular expression for validating the 'name' field.  Allowing only alphanumeric characters and spaces.
NAME_REGEX = r"^[a-zA-Z0-9\s]+$"

@app.route('/', methods=['POST'])
def process_payload():
    """
    Processes a POST request, extracts the 'name' field from the payload,
    validates it, and returns it in the response.
    """

    # 1. & 5. Validate request data (including headers, cookies, etc. - example below)
    if request.headers.get('Content-Type') != 'application/json':
        return "Invalid Content-Type", 400

    # 10. Generate a pseudorandom value and set it as a cookie.
    session_token = secrets.token_hex(16)
    resp = make_response()
    resp.set_cookie('session_token', session_token, httponly=True, secure=True, samesite='Lax') # Secure and samesite attributes for production

    try:
        payload = request.get_json()
        if not isinstance(payload, dict):
            return "Invalid JSON payload", 400

        if 'name' in payload:
            name = payload['name']

            # 4. & 8. Stringent allowlist validation using regex
            if not isinstance(name, str) or not re.match(NAME_REGEX, name):
                return "Invalid name format.  Only alphanumeric characters and spaces are allowed.", 400

            # 9. Escape the output to prevent XSS
            escaped_name = html.escape(name)

            # 7. Specify encoding in the HTTP header
            resp.headers['Content-Type'] = 'text/html; charset=utf-8'
            resp.data = f"<h1>Hello, {escaped_name}!</h1>"  # Constructing the webpage with escaped input
            return resp

        else:
            return "Name field not found in payload", 400

    except Exception as e:
        print(f"Error processing payload: {e}") # Log the error for debugging
        return "Error processing payload", 500


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    return response


if __name__ == '__main__':
    #  Never run this in production.  Use a production-ready WSGI server.
    app.run(debug=True, host='0.0.0.0', port=5000)

