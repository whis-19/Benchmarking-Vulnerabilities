from flask import Flask, request, make_response
import secrets
import re

app = Flask(__name__)

@app.route("/getcookie")
def getcookie():
    '''
    Get the cookie from the request using 'cookie' and set it as a cookie in the response.
    :return: The response with the cookie.
    '''
    cookie_value = request.args.get('cookie')

    # Validate the cookie value using a stringent allowlist.  This example allows only alphanumeric characters and underscores.
    if not cookie_value or not re.match(r"^[a-zA-Z0-9_]+$", cookie_value):
        return "Invalid cookie value", 400  # Return an error if the value is invalid

    # Generate a unique and unpredictable nonce for CSRF protection (Double-Submit Cookie)
    csrf_token = secrets.token_hex(16)

    # Create the response
    resp = make_response("Cookie set successfully")

    # Set the cookie with HttpOnly flag and Secure flag (if running on HTTPS)
    resp.set_cookie('mycookie', cookie_value, httponly=True, samesite='Lax') # Added samesite for additional security
    resp.set_cookie('csrf_token', csrf_token, httponly=False, samesite='Lax') # CSRF token accessible by JavaScript

    # Set the CSRF token as a hidden field in a form (example - you'd need to render a form in a real application)
    # This is just an example; you'd typically render a full HTML form.
    # form_html = f'<form method="POST"><input type="hidden" name="csrf_token" value="{csrf_token}"></form>'
    # resp.data = form_html

    # Set the content type to ensure proper encoding
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'

    return resp

@app.route('/process_form', methods=['POST'])
def process_form():
    """
    Example route to process a form submission with CSRF protection.
    """
    csrf_token_sent = request.form.get('csrf_token')
    csrf_token_cookie = request.cookies.get('csrf_token')

    if not csrf_token_sent or not csrf_token_cookie or csrf_token_sent != csrf_token_cookie:
        return "CSRF token mismatch", 400

    # Process the form data here (after CSRF validation)
    # ...

    return "Form processed successfully"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

