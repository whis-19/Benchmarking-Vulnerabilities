import cgi
import html
import os
import secrets
import http.cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# --- Configuration ---
SERVER_HOST = "localhost"
SERVER_PORT = 8000
SESSION_COOKIE_NAME = "sessionid"
NONCE_LENGTH = 16  # Length of the nonce in bytes
ALLOWED_USERNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"  # Strict allowlist for username
# --- End Configuration ---


def generate_nonce():
    """Generates a cryptographically secure random nonce."""
    return secrets.token_hex(NONCE_LENGTH)


def validate_username(username):
    """Validates the username against a strict allowlist."""
    if not username:
        return False
    for char in username:
        if char not in ALLOWED_USERNAME_CHARS:
            return False
    return True


def get_session_id(headers):
    """Retrieves the session ID from the request headers."""
    if 'Cookie' in headers:
        cookies = http.cookies.SimpleCookie()
        cookies.load(headers['Cookie'])
        if SESSION_COOKIE_NAME in cookies:
            return cookies[SESSION_COOKIE_NAME].value
    return None


def create_session_cookie():
    """Creates a new session cookie with HttpOnly flag."""
    session_id = secrets.token_hex(16)  # Generate a secure session ID
    cookie = http.cookies.SimpleCookie()
    cookie[SESSION_COOKIE_NAME] = session_id
    cookie[SESSION_COOKIE_NAME]['httponly'] = True  # Important: HttpOnly flag
    cookie[SESSION_COOKIE_NAME]['path'] = '/'  # Set the path for the cookie
    return cookie


class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == '/hello':
            self.http_hello_page()
        elif path == '/form':
            self.show_form()
        else:
            self.send_error(404, 'File Not Found')

    def do_POST(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == '/submit':
            self.handle_form_submission()
        else:
            self.send_error(404, 'File Not Found')

    def show_form(self):
        """Displays a form with a nonce for CSRF protection."""
        session_id = get_session_id(self.headers)
        if not session_id:
            cookie = create_session_cookie()
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            for morsel in cookie.values():
                self.send_header('Set-Cookie', morsel.OutputString())
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()

        nonce = generate_nonce()
        # Store the nonce in the session (in a real app, this would be server-side)
        # For this example, we'll just store it in a hidden field and rely on double-submit cookie
        form_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Hello Form</title>
        </head>
        <body>
            <h1>Enter your username:</h1>
            <form method="POST" action="/submit">
                <input type="hidden" name="csrf_nonce" value="{nonce}">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username"><br><br>
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """
        self.wfile.write(form_html.encode('utf-8'))

    def handle_form_submission(self):
        """Handles the form submission, validating the nonce and username."""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        form_data = parse_qs(post_data)

        # CSRF Protection: Double-Submit Cookie Method
        csrf_nonce_submitted = form_data.get('csrf_nonce', [''])[0]
        username = form_data.get('username', [''])[0]

        # Validate the username
        if not validate_username(username):
            self.send_response(400)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write("Invalid username.  Only alphanumeric characters and underscores are allowed.".encode('utf-8'))
            return

        # Validate the nonce (double-submit cookie)
        session_id = get_session_id(self.headers)
        if not session_id:
            self.send_response(400)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write("No session cookie found.".encode('utf-8'))
            return

        # In a real application, you would compare the submitted nonce with the nonce stored server-side
        # For this example, we're just checking that a nonce was submitted.  This is *not* sufficient for real security.
        if not csrf_nonce_submitted:
            self.send_response(400)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write("CSRF nonce missing.".encode('utf-8'))
            return

        # Sanitize the username to prevent XSS
        sanitized_username = html.escape(username)

        # Construct the response
        response_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Hello {sanitized_username}</title>
        </head>
        <body>
            <h1>Hello, {sanitized_username}!</h1>
        </body>
        </html>
        """

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(response_html.encode('utf-8'))

    def http_hello_page(self):
        """Handles the /hello request."""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write("<h1>Hello, World!</h1>".encode('utf-8'))


def run_server():
    server_address = (SERVER_HOST, SERVER_PORT)
    httpd = HTTPServer(server_address, MyHTTPRequestHandler)
    print(f"Server running on http://{SERVER_HOST}:{SERVER_PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("Server stopped.")


if __name__ == '__main__':
    run_server()

