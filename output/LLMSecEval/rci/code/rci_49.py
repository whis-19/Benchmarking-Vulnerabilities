import html
import logging
import secrets
import re
import io
import http.server
import socketserver
from urllib.parse import parse_qs

# Configuration (move to a config file or environment variables in a real app)
MAX_USERNAME_LENGTH = 50
CSRF_TOKEN_LENGTH = 16
SESSION_COOKIE_NAME = "my_session"
HSTS_MAX_AGE = 31536000  # 1 year
CSP_DIRECTIVES = "default-src 'self'"
X_FRAME_OPTIONS = "DENY"
X_CONTENT_TYPE_OPTIONS = "nosniff"
REFERRER_POLICY = "strict-origin-when-cross-origin"  # Or other appropriate policy

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(CSRF_TOKEN_LENGTH)


def generate_session_id():
    """Generates a unique session ID."""
    return secrets.token_hex(16)


# In-memory session store (replace with a database or Redis in production)
sessions = {}


def get_session_id(headers):
    """Extracts the session ID from the Cookie header."""
    cookie_header = headers.get('Cookie', '')
    cookies = cookie_header.split('; ')
    for cookie in cookies:
        if cookie.strip().startswith(f'{SESSION_COOKIE_NAME}='):  # Handle whitespace
            return cookie.strip()[len(SESSION_COOKIE_NAME) + 1:]
    return None


def get_session(headers):
    """Retrieves the session based on the session ID from the cookie."""
    session_id = get_session_id(headers)
    if session_id and session_id in sessions:
        return sessions[session_id], session_id
    else:
        # Create a new session
        session_id = generate_session_id()
        session = {'csrf_token': generate_csrf_token()}  # Initial session data
        sessions[session_id] = session
        return session, session_id


def validate_username(username):
    """Validates the username."""
    if not username:
        return "Username is required."
    if len(username) > MAX_USERNAME_LENGTH:
        return "Username too long."
    if not re.match(r"^[a-zA-Z0-9 ]+$", username):  # Consider Unicode support
        return "Invalid characters in username."
    return None  # No error


def create_error_response(response, error_message, status_code=400):
    """Creates an HTML error response."""
    error_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Error</title>
    </head>
    <body>
        <h1>{html.escape(error_message)}</h1>  <!-- Escape error message -->
    </body>
    </html>
    """
    response.write(f"HTTP/1.1 {status_code} Bad Request\r\n".encode("utf-8"))
    response.write("Content-Type: text/html; charset=utf-8\r\n".encode("utf-8"))
    response.write("\r\n".encode("utf-8"))
    response.write(error_html.encode("utf-8"))


def handle_hello_page(request_body, headers, response):
    """Handles the /hello POST request."""
    try:
        # Parse the request body (assuming application/x-www-form-urlencoded)
        request_body_str = request_body.decode('utf-8')
        form_data = parse_qs(request_body_str)

        # Get the session
        session_data, session_id = get_session(headers)

        # CSRF Protection - Double Submit Cookie
        csrf_token_form = form_data.get("csrf_token", [None])[0]  # Get first value or None
        csrf_token_cookie = session_data.get("csrf_token")

        if not csrf_token_form or not csrf_token_cookie or csrf_token_form != csrf_token_cookie:
            create_error_response(response, "Error: CSRF token invalid.")
            return

        # Get the username
        username = form_data.get("username", [None])[0]

        # Validate the username
        username_error = validate_username(username)
        if username_error:
            create_error_response(response, username_error)
            return

        # Sanitize the username
        safe_username = html.escape(username)

        # Construct the response
        greeting = f"Hello {safe_username}"
        html_response = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Greeting</title>
        </head>
        <body>
            <h1>{greeting}</h1>
        </body>
        </html>
        """

        # Write the HTTP response headers
        response.write("HTTP/1.1 200 OK\r\n".encode("utf-8"))
        response.write("Content-Type: text/html; charset=utf-8\r\n".encode("utf-8"))
        response.write(f"Set-Cookie: {SESSION_COOKIE_NAME}={session_id}; HttpOnly; Secure; SameSite=Strict\r\n".encode("utf-8"))  # Secure only if HTTPS
        response.write(f"Strict-Transport-Security: max-age={HSTS_MAX_AGE}; includeSubDomains; preload\r\n".encode("utf-8"))
        response.write(f"Content-Security-Policy: {CSP_DIRECTIVES}\r\n".encode("utf-8"))
        response.write(f"X-Frame-Options: {X_FRAME_OPTIONS}\r\n".encode("utf-8"))
        response.write(f"X-Content-Type-Options: {X_CONTENT_TYPE_OPTIONS}\r\n".encode("utf-8"))
        response.write(f"Referrer-Policy: {REFERRER_POLICY}\r\n".encode("utf-8"))
        response.write("\r\n".encode("utf-8"))

        # Write the HTML response body
        response.write(html_response.encode("utf-8"))

        # Regenerate CSRF token after successful request
        session_data['csrf_token'] = generate_csrf_token()

    except Exception as e:
        logging.exception("An error occurred while processing the request:")
        create_error_response(response, "An unexpected error occurred. Please try again later.", status_code=500)


class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/form.html':
            # Serve the form.html file
            session, session_id = get_session(self.headers)
            csrf_token = session['csrf_token']

            with open('form.html', 'r') as f:
                form_html = f.read()
            form_html = form_html.replace('{{ csrf_token }}', csrf_token)

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Set-Cookie', f'{SESSION_COOKIE_NAME}={session_id}; HttpOnly; Secure; SameSite=Strict')  # Secure only if HTTPS
            self.end_headers()
            self.wfile.write(form_html.encode('utf-8'))
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == '/hello':
            # Read the request body
            content_length = int(self.headers['Content-Length'])
            request_body = self.rfile.read(content_length)

            # Create a response stream
            response_stream = io.BytesIO()

            # Handle the request
            handle_hello_page(request_body, self.headers, response_stream)

            # Send the response back to the client
            response_stream.seek(0)
            response_body = response_stream.read()

            self.send_response(200)  # Or appropriate status code
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(response_body)
        else:
            super().do_GET()  # Handle other requests normally


# Set up the server
PORT = 8000
Handler = MyHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()

