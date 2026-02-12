from flask import Flask, request, make_response
import secrets
import re

app = Flask(__name__)

# CSRF protection using double-submitted cookies
def generate_csrf_token():
    """Generates a unique CSRF token."""
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    """Sets the CSRF cookie in the response."""
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure, HttpOnly, and Strict SameSite
    return csrf_token

def validate_csrf_token(request):
    """Validates the CSRF token from the request against the cookie."""
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_form = request.form.get('csrf_token')  # Assuming it's in a form

    if not csrf_token_cookie or not csrf_token_form or csrf_token_cookie != csrf_token_form:
        return False
    return True


@app.route("/getcookie", methods=['GET', 'POST'])
def getcookie():
    """
    Get the cookie from the request (validated) and set it as a cookie in the response.
    :return: The response with the cookie.
    """
    if request.method == 'POST':
        if not validate_csrf_token(request):
            return "CSRF token validation failed", 400

        cookie_value = request.form.get('cookie')  # Get cookie value from form

        # Input validation and sanitization:  Strict allowlist for cookie value
        if not cookie_value:
            return "Cookie value is missing", 400

        if not re.match(r"^[a-zA-Z0-9]+$", cookie_value):  # Example: Alphanumeric only
            return "Invalid cookie value.  Only alphanumeric characters allowed.", 400

        response = make_response("Cookie set successfully")
        response.set_cookie('mycookie', cookie_value, httponly=True, secure=True, samesite='Strict') # Secure, HttpOnly, and Strict SameSite
        response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
        return response
    else: #GET request
        # Generate CSRF token and set the cookie
        response = make_response('''
            <form method="post">
            <input type="hidden" name="csrf_token" value="">
            Cookie Value: <input type="text" name="cookie"><br>
            <input type="submit" value="Set Cookie">
            </form>
        ''')
        csrf_token = set_csrf_cookie(response)
        response.data = response.data.replace(b'name="csrf_token" value="">', f'name="csrf_token" value="{csrf_token}">'.encode('utf-8'))
        response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
        return response


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc') # Enable HTTPS with adhoc certificate for testing

