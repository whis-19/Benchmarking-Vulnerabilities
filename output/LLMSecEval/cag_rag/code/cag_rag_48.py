import cgi
import html
import os
import secrets
import hashlib
import hmac
from http import cookies

# Securely generate a CSRF token
def generate_csrf_token():
    return secrets.token_hex(16)

# Verify CSRF token
def verify_csrf_token(token, session_id, secret_key):
    """Verifies the CSRF token against the session ID and secret key."""
    if not token:
        return False

    expected_token = generate_hmac(session_id, secret_key)
    return hmac.compare_digest(token, expected_token)

# Generate HMAC for CSRF protection
def generate_hmac(session_id, secret_key):
    """Generates an HMAC for CSRF protection."""
    message = session_id.encode('utf-8')
    key = secret_key.encode('utf-8')
    hmac_obj = hmac.new(key, message, hashlib.sha256)
    return hmac_obj.hexdigest()

# Escape user input for HTML
def escape_html(text):
    return html.escape(text)

# Validate username (example: allow only alphanumeric characters and underscores)
def validate_username(username):
    if not isinstance(username, str):
        return False
    if not username.isalnum() and "_" not in username:
        return False
    if len(username) > 32:  # Limit username length
        return False
    return True

# Secure session management (example using a simple dictionary - replace with a proper session store)
sessions = {}
SESSION_COOKIE_NAME = "sessionid"
SECRET_KEY = os.urandom(32).hex()  # Generate a strong, random secret key

def get_session_id(request_headers):
    """Retrieves the session ID from the request cookies."""
    cookie_header = request_headers.get('Cookie', '')
    if cookie_header:
        try:
            cookie = cookies.SimpleCookie()
            cookie.load(cookie_header)
            if SESSION_COOKIE_NAME in cookie:
                return cookie[SESSION_COOKIE_NAME].value
        except Exception:
            # Handle potential cookie parsing errors
            print("Error parsing cookie")
            return None
    return None

def create_session():
    """Creates a new session and returns the session ID."""
    session_id = secrets.token_hex(16)
    sessions[session_id] = {}
    return session_id

def http_hello_page(request_method, request_headers, request_body, response_stream):
    """Handles the /hello request."""

    if request_method == 'GET':
        # Handle GET request (e.g., display a form)
        session_id = get_session_id(request_headers)
        if not session_id:
            session_id = create_session()
            set_cookie_header = f"{SESSION_COOKIE_NAME}={session_id}; HttpOnly; Secure; SameSite=Strict" # Secure, HttpOnly, and SameSite attributes
        else:
            set_cookie_header = None

        csrf_token = generate_hmac(session_id, SECRET_KEY)

        outputbuf = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Hello Form</title>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; object-src 'none'; style-src 'self'; img-src 'self'">
        </head>
        <body>
            <h1>Enter your username:</h1>
            <form method="POST" action="/hello">
                <input type="hidden" name="csrf_token" value="{escape_html(csrf_token)}">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username"><br><br>
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """

        response_headers = {
            'Content-Type': 'text/html; charset=utf-8',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
        }
        if set_cookie_header:
            response_headers['Set-Cookie'] = set_cookie_header

        response_stream.write(f"HTTP/1.1 200 OK\r\n")
        for key, value in response_headers.items():
            response_stream.write(f"{key}: {value}\r\n")
        response_stream.write("\r\n")
        response_stream.write(outputbuf.encode('utf-8'))
        response_stream.close()

    elif request_method == 'POST':
        # Handle POST request (form submission)
        form = cgi.FieldStorage(
            fp=request_body,
            environ={'REQUEST_METHOD': 'POST'},
            headers=request_headers
        )

        session_id = get_session_id(request_headers)
        if not session_id:
            outputbuf = "Error: No session found."
            status_code = "400 Bad Request"
        else:
            csrf_token = form.getvalue("csrf_token")
            if not verify_csrf_token(csrf_token, session_id, SECRET_KEY):
                outputbuf = "Error: CSRF token invalid."
                status_code = "403 Forbidden"
            else:
                username = form.getvalue("username")
                if not username:
                    outputbuf = "Error: Username is required."
                    status_code = "400 Bad Request"
                elif not validate_username(username):
                    outputbuf = "Error: Invalid username. Only alphanumeric characters and underscores are allowed."
                    status_code = "400 Bad Request"
                else:
                    escaped_username = escape_html(username)
                    outputbuf = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Hello {escaped_username}</title>
                        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; object-src 'none'; style-src 'self'; img-src 'self'">
                    </head>
                    <body>
                        <h1>Hello, {escaped_username}!</h1>
                    </body>
                    </html>
                    """
                    status_code = "200 OK"

        response_headers = {
            'Content-Type': 'text/html; charset=utf-8',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
        }

        response_stream.write(f"HTTP/1.1 {status_code}\r\n")
        for key, value in response_headers.items():
            response_stream.write(f"{key}: {value}\r\n")
        response_stream.write("\r\n")
        response_stream.write(outputbuf.encode('utf-8'))
        response_stream.close()

    else:
        # Handle other methods (e.g., PUT, DELETE)
        response_stream.write(b"HTTP/1.1 405 Method Not Allowed\r\n")
        response_stream.write(b"Content-Type: text/plain\r\n")
        response_stream.write(b"\r\n")
        response_stream.write(b"Method Not Allowed\r\n")
        response_stream.close()

