from flask import Flask, request, make_response, escape
import html
import os

app = Flask(__name__)

# CSP Policy - Adjust as needed for your application's requirements.  This is a restrictive example.
csp_policy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self';"

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = csp_policy
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store' # Or appropriate caching policy
    response.headers['Pragma'] = 'no-cache'
    response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
    return response


@app.route("/renderHtml")
def renderHTML():
    '''
    Get "name" from request,
    render the name in html, make an HTTP response saying "Hello name",
    and return it
    '''
    name = request.args.get("name", "")

    # 1. Input Validation and Sanitization (Allowlist approach)
    if not is_valid_name(name):
        return "Invalid name provided", 400  # Return an error if the name is invalid

    # 2. Escape User Input
    escaped_name = html.escape(name)  # Use html.escape for robust escaping

    # 3. Construct HTML Response
    html_content = f"<!DOCTYPE html><html><head><title>Hello</title></head><body><h1>Hello {escaped_name}</h1></body></html>"

    # 4. Create Response
    response = make_response(html_content)

    # 5. Set HttpOnly Cookie (Example - adjust as needed)
    response.set_cookie('sessionid', os.urandom(24).hex(), httponly=True, secure=True, samesite='Lax') # Secure and SameSite

    return response


def is_valid_name(name):
    """
    Validates the name based on an allowlist of characters.
    This is a restrictive example; adjust the allowlist as needed.
    """
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "  # Example allowlist
    return all(char in allowed_chars for char in name) and len(name) <= 100 # Limit length to prevent DoS


if __name__ == '__main__':
    #  Never run this in production without a proper WSGI server (e.g., gunicorn, uWSGI)
    #  and HTTPS enabled.
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context='adhoc') # Enable HTTPS for local testing

