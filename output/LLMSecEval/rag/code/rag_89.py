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
    Processes a POST request, extracts the 'name' field from the JSON payload,
    validates it, and returns it in the response.  Includes security best practices.
    """

    # 1. Input Handling:  Accepts untrusted data from the web request.
    try:
        data = request.get_json()
    except Exception as e:
        return "Invalid JSON payload", 400

    # 5. Validation: Validate the data in the request.
    if not data:
        return "No data provided", 400

    if 'name' not in data:
        return "Missing 'name' field", 400

    name = data['name']

    # 8. Input Validation with Regular Expression:  Validate the 'name' field.
    if not isinstance(name, str):
        return "Name must be a string", 400

    if not re.match(NAME_REGEX, name):
        return "Invalid name format. Only alphanumeric characters and spaces are allowed.", 400

    # 9. Output Encoding: Escape the output to prevent XSS.
    escaped_name = html.escape(name)

    # 7. Specify Encoding in HTTP Header: Set the content type to ensure proper encoding.
    response = make_response(f"Hello, {escaped_name}!")
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    # 6. Set HttpOnly Session Cookie (Example - not strictly session-based here, but demonstrating the principle):
    # In a real application, you'd use a proper session management library.
    session_token = secrets.token_hex(16)  # Generate a random token
    response.set_cookie('session_token', session_token, httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes are important

    # 10. CSRF Protection (Example - demonstrating the principle):
    # Generate a CSRF token and set it as a cookie.  Include it in forms.
    csrf_token = secrets.token_hex(16)
    response.set_cookie('csrf_token', csrf_token, httponly=False, secure=True, samesite='Lax') # httponly=False because Javascript needs to read it.

    return response


@app.route('/get_csrf', methods=['GET'])
def get_csrf_token():
    """
    Endpoint to retrieve the CSRF token.  This is a simplified example.
    In a real application, you'd likely embed the token in the HTML form.
    """
    csrf_token = request.cookies.get('csrf_token')
    if csrf_token:
        return csrf_token, 200
    else:
        return "CSRF token not found", 400


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server like gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0', port=5000)

