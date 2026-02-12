import cgi
import html
import os
import secrets
import hashlib
import hmac
from http import cookies

# Securely generate a CSRF token
def generate_csrf_token():
    return secrets.token_hex(32)

# Verify the CSRF token
def verify_csrf_token(session, token):
    if 'csrf_token' not in session:
        return False
    return hmac.compare_digest(session['csrf_token'], token)

# Escape user input for HTML output
def escape_html(text):
    return html.escape(text, quote=True)

# Validate username (allowlist approach)
def validate_username(username):
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"  # Example allowlist
    if not all(char in allowed_chars for char in username):
        return False, "Invalid characters in username."
    if not (1 <= len(username) <= 32): # Example length restriction
        return False, "Username must be between 1 and 32 characters."
    return True, None

def http_hello_page(environ, start_response):
    """
    Handles the /hello request.  Reads the username from the request body,
    constructs an HTML response, and sends it back to the client.
    """

    # 1. Read the request body (username)
    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except (ValueError):
        request_body_size = 0

    request_body = environ['wsgi.input'].read(request_body_size).decode('utf-8')

    # Parse the request body (assuming it's a simple form)
    form_data = cgi.parse_qs(request_body)
    username = form_data.get('username', [''])[0]  # Get the first username value, default to empty string

    # 2. Validate and sanitize the username
    is_valid, error_message = validate_username(username)
    if not is_valid:
        status = '400 Bad Request'
        headers = [('Content-type', 'text/plain; charset=utf-8')]
        start_response(status, headers)
        return [error_message.encode()]

    escaped_username = escape_html(username)

    # 3. Session management (example using a simple cookie)
    session = {}
    cookie_string = environ.get('HTTP_COOKIE', '')
    cookies_obj = cookies.SimpleCookie()
    cookies_obj.load(cookie_string)

    session_id = cookies_obj.get('sessionid')
    if session_id:
        session_id = session_id.value
        # In a real application, you would load the session data from a database
        # based on the session_id.  For this example, we'll just assume it's empty.
    else:
        session_id = secrets.token_hex(16)  # Generate a new session ID
        session['csrf_token'] = generate_csrf_token() # Generate CSRF token for the session

    # 4. CSRF protection (example)
    csrf_token = session.get('csrf_token')
    if not csrf_token:
        csrf_token = generate_csrf_token()
        session['csrf_token'] = csrf_token

    # 5. Construct the HTML response (with CSP and escaped username)
    outputbuf = f"""<!DOCTYPE html>
    <html>
    <head>
        <title>Hello Page</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;">
    </head>
    <body>
        <h1>Hello, {escaped_username}!</h1>
        <p>Welcome to the secure hello page.</p>

        <form method="POST" action="/hello">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <label for="username">Update Username:</label>
            <input type="text" id="username" name="username" value="{escaped_username}">
            <button type="submit">Submit</button>
        </form>

    </body>
    </html>
    """

    # 6. Set the response headers
    status = '200 OK'
    headers = [('Content-type', 'text/html; charset=utf-8'),
               ('Content-Security-Policy', "default-src 'self'; script-src 'none'; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"),
               ('Set-Cookie', f'sessionid={session_id}; HttpOnly; Secure; SameSite=Strict')] # Secure, HttpOnly, and SameSite attributes
    start_response(status, headers)

    # 7. Return the response body
    return [outputbuf.encode('utf-8')]

# Example usage (for testing - not a complete WSGI server)
if __name__ == '__main__':
    # Simulate a WSGI environment
    environ = {
        'REQUEST_METHOD': 'POST',
        'PATH_INFO': '/hello',
        'CONTENT_LENGTH': '20',
        'wsgi.input': open('request_body.txt', 'rb')  # Create a file named request_body.txt with "username=test_user" inside
    }

    def start_response(status, headers):
        print("Status:", status)
        print("Headers:", headers)

    response = http_hello_page(environ, start_response)
    print("Response:", response[0].decode('utf-8'))

