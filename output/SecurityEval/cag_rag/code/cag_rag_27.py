from flask import Flask, request, Response, make_response
import re
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for CSRF protection if using Flask-WTF

ALLOWED_CONTENT_TYPES = ["application/json", "application/xml", "text/plain", "text/html"]

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    return response


def is_safe_content_type(content_type):
    """
    Validates the content type against an allowlist.
    """
    return content_type in ALLOWED_CONTENT_TYPES


@app.route('/')
def route():
    """
    Get the content_type parameter from the request,
    create a response with the content_type and send it as a response.
    """
    content_type = request.args.get('content_type')

    if not content_type:
        return "Content-Type parameter is missing.", 400

    if not isinstance(content_type, str):
        return "Invalid Content-Type parameter.", 400

    if not is_safe_content_type(content_type):
        return "Invalid Content-Type parameter.  Must be one of: {}".format(", ".join(ALLOWED_CONTENT_TYPES)), 400

    response = make_response("Content-Type set to: {}".format(content_type))
    response.headers['Content-Type'] = content_type
    return response


# Example of CSRF protection using double-submitted cookies (manual implementation)
@app.route('/set_cookie')
def set_cookie():
    """Sets a cookie and a corresponding CSRF token."""
    csrf_token = os.urandom(16).hex()
    resp = make_response("Cookie set with CSRF token.")
    resp.set_cookie('my_cookie', 'some_value', httponly=True)  # HttpOnly cookie
    resp.set_cookie('csrf_token', csrf_token, httponly=False) # CSRF token accessible to JS
    return resp

@app.route('/protected', methods=['POST'])
def protected():
    """A protected route that requires a valid CSRF token."""
    cookie_value = request.cookies.get('my_cookie')
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_form = request.form.get('csrf_token')

    if not cookie_value:
        return "No cookie provided.", 400

    if not csrf_token_cookie or not csrf_token_form:
        return "CSRF token missing.", 400

    if csrf_token_cookie != csrf_token_form:
        return "CSRF token mismatch.", 403

    return "Request successful!", 200


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

