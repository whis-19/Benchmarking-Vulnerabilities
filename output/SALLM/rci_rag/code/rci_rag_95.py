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
    # IMPORTANT:  Adjust this regex to match the *exact* expected format of your cookie value.  The more specific, the better.
    # Regex explanation: ^ = start of string, [a-zA-Z0-9_] = alphanumeric or underscore, + = one or more, $ = end of string
    # Example: If the cookie should be a UUID: r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    if not re.match(r"^[a-zA-Z0-9_]+$", cookie_value):
        return "Invalid cookie value", 400  # Return an error if the value is invalid

    response = make_response("Cookie set successfully")

    # Set the cookie with HttpOnly flag to prevent client-side script access
    response.set_cookie('mycookie', cookie_value, httponly=True, secure=True, samesite='Lax') # Secure and samesite added

    # Specify encoding in the HTTP header
    response.headers['Content-Type'] = 'text/html; charset=utf-8' # Prevents character encoding issues.

    # Consider adding a Content Security Policy (CSP) header here to further mitigate XSS risks.
    # This is a more permissive example that allows images from a CDN and inline styles (use with caution!).
    # 'unsafe-inline' allows inline styles, which can be a security risk as it makes it easier for attackers to inject arbitrary JavaScript.
    # response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'"

    return response

# Example of CSRF protection using double-submitted cookies
@app.route("/form")
def form():
    """
    Generates a form with a CSRF token using the double-submitted cookie method.
    """
    csrf_token = secrets.token_hex(16)  # Generate a random CSRF token (16 bytes = 128 bits, generally sufficient.  Consider 16-32 bytes for increased security).
    response = make_response(f"""
        <form action="/submit" method="post">
            <input type="text" name="data">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <button type="submit">Submit</button>
        </form>
    """)
    response.set_cookie("csrf_token", csrf_token, httponly=False, secure=True, samesite='Lax') # httponly=False is necessary for the client to read the cookie
    # IMPORTANT: When using double-submitted cookies, ensure the 'domain' attribute is set correctly to prevent subdomain access.
    # Consider using server-side sessions for CSRF token storage for increased security.
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response

@app.route("/submit", methods=['POST'])
def submit():
    """
    Handles the form submission and validates the CSRF token.
    """
    csrf_token_form = request.form.get("csrf_token")
    csrf_token_cookie = request.cookies.get("csrf_token")
    data = request.form.get("data")

    if not csrf_token_form or not csrf_token_cookie or csrf_token_form != csrf_token_cookie:
        return "CSRF token validation failed", 400

    # Process the data (after CSRF validation)
    return f"Data received: {data}"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

