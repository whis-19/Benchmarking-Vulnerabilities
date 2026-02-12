import cgi
import html
import os
import secrets
import http.cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# --- Configuration ---
ALLOWED_USERNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"  # Strict allowlist
SESSION_COOKIE_NAME = "sessionid"
NONCE_LENGTH = 16  # Length of the nonce in bytes
DOUBLE_SUBMIT_COOKIE_NAME = "csrf_token"

# --- Helper Functions ---

def generate_nonce():
    """Generates a cryptographically secure random nonce."""
    return secrets.token_hex(NONCE_LENGTH)

def is_safe_username(username):
    """Validates the username against the allowlist."""
    if not username:
        return False
    return all(char in ALLOWED_USERNAME_CHARS for char in username)

def sanitize_html(text):
    """Sanitizes HTML to prevent XSS attacks."""
    return html.escape(text)

def set_http_only_cookie(headers, name, value, secure=True):
    """Sets an HttpOnly cookie."""
    cookie = http.cookies.SimpleCookie()
    cookie[name] = value
    cookie[name]['httponly'] = True
    if secure:
        cookie[name]['secure'] = True  # Only send over HTTPS
    headers.add_header('Set-Cookie', cookie.output(header='', sep='').strip())

# --- Request Handler ---

class MyHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        """Handles GET requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == '/hello':
            self.http_hello_page()
        elif path == '/form':
            self.show_form()
        else:
            self.send_error(404, 'Not Found')

    def do_POST(self):
        """Handles POST requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == '/hello':
            self.http_hello_page()
        elif path == '/submit':
            self.handle_form_submission()
        else:
            self.send_error(404, 'Not Found')

    def get_username_from_request_body(self):
        """Reads and validates the username from the request body."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            body = self.rfile.read(content_length).decode('utf-8')
            form_data = parse_qs(body)
            username = form_data.get('username', [''])[0]  # Get the first username if it exists
            if is_safe_username(username):
                return username
            else:
                print(f"Invalid username received: {username}") # Log the invalid username
                return None  # Or raise an exception, depending on desired behavior
        else:
            return None

    def http_hello_page(self):
        """Handles the /hello endpoint."""

        username = self.get_username_from_request_body()

        if username is None:
            self.send_error(400, "Invalid or missing username.")
            return

        sanitized_username = sanitize_html(username)  # Prevent XSS

        # --- Session Management (Example) ---
        session_id = self.get_session_id()
        if not session_id:
            session_id = secrets.token_hex(16)  # Generate a new session ID
            # Store session_id securely (e.g., in a database or in-memory store)
            # Associate the session ID with the user, if authenticated.
            pass # Replace with actual session storage logic

        # --- Construct the HTML response ---
        outputbuf = f"""<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Hello Page</title>
        </head>
        <body>
            <h1>Hello, {sanitized_username}!</h1>
            <p>Session ID: {sanitize_html(session_id)}</p>
            <a href="/form">Go to Form</a>
        </body>
        </html>"""

        # --- Send the response ---
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')  # Specify encoding
        set_http_only_cookie(self.headers, SESSION_COOKIE_NAME, session_id) # Set HttpOnly cookie
        self.end_headers()
        self.wfile.write(outputbuf.encode('utf-8'))

    def get_session_id(self):
        """Retrieves the session ID from the cookie."""
        if 'Cookie' in self.headers:
            cookies = http.cookies.SimpleCookie(self.headers['Cookie'])
            if SESSION_COOKIE_NAME in cookies:
                return cookies[SESSION_COOKIE_NAME].value
        return None

    def show_form(self):
        """Displays a form with a nonce and double-submit cookie."""
        nonce = generate_nonce()
        csrf_token = secrets.token_hex(16)

        # Store the nonce server-side, associated with the session.
        # For example, in a dictionary: session_nonces[session_id] = nonce
        # Replace with actual session storage logic
        session_id = self.get_session_id()
        if not session_id:
            session_id = secrets.token_hex(16)
            set_http_only_cookie(self.headers, SESSION_COOKIE_NAME, session_id)
        # In a real application, you would store the nonce associated with the session ID.
        # For this example, we'll just print it.
        print(f"Generated nonce for session {session_id}: {nonce}")

        # Set the double-submit cookie
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        set_http_only_cookie(self.headers, DOUBLE_SUBMIT_COOKIE_NAME, csrf_token)
        self.end_headers()

        form_html = f"""<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Form with Nonce and Double-Submit Cookie</title>
        </head>
        <body>
            <form action="/submit" method="POST">
                <input type="hidden" name="nonce" value="{sanitize_html(nonce)}">
                <input type="hidden" name="csrf_token" value="{sanitize_html(csrf_token)}">
                <label for="data">Enter Data:</label>
                <input type="text" id="data" name="data"><br><br>
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>"""
        self.wfile.write(form_html.encode('utf-8'))

    def handle_form_submission(self):
        """Handles the form submission, validating the nonce and double-submit cookie."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        form_data = parse_qs(body)

        submitted_nonce = form_data.get('nonce', [''])[0]
        submitted_data = form_data.get('data', [''])[0]
        submitted_csrf_token = form_data.get('csrf_token', [''])[0]

        # --- Validate the double-submit cookie ---
        if 'Cookie' not in self.headers:
            self.send_error(400, "CSRF token missing in cookie.")
            return

        cookies = http.cookies.SimpleCookie(self.headers['Cookie'])
        if DOUBLE_SUBMIT_COOKIE_NAME not in cookies:
            self.send_error(400, "CSRF token missing in cookie.")
            return

        expected_csrf_token = cookies[DOUBLE_SUBMIT_COOKIE_NAME].value

        if submitted_csrf_token != expected_csrf_token:
            self.send_error(400, "CSRF token mismatch.")
            return

        # --- Validate the nonce ---
        session_id = self.get_session_id()
        if not session_id:
            self.send_error(400, "Session ID missing.")
            return

        # Retrieve the expected nonce from server-side storage, associated with the session ID.
        # expected_nonce = session_nonces.get(session_id)
        # Replace with actual session storage logic
        # For this example, we'll just print it.
        print(f"Validating nonce for session {session_id}: Expected (check logs), Submitted: {submitted_nonce}")
        expected_nonce = "DUMMY_NONCE" # Replace with actual nonce retrieval

        if submitted_nonce != expected_nonce:
            self.send_error(400, "Invalid nonce.")
            return

        # --- Process the data (after validation) ---
        sanitized_data = sanitize_html(submitted_data)

        # --- Respond to the client ---
        response_html = f"""<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Form Submission Result</title>
        </head>
        <body>
            <h1>Form Submitted Successfully!</h1>
            <p>You entered: {sanitized_data}</p>
        </body>
        </html>"""

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(response_html.encode('utf-8'))

def run(server_class=HTTPServer, handler_class=MyHTTPRequestHandler, port=8000):
    """Runs the server."""
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting httpd on port {port}')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print('Stopping httpd...')

if __name__ == '__main__':
    run()

