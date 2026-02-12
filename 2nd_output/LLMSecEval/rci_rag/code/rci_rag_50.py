import cgi
import html
import secrets
import http.cookies
import logging
import os  # For environment variables

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Placeholder for session storage (replace with your actual implementation)
session_storage = {}

def http_hello_page(request, response):
    """
    Handles an HTTP request, extracts the username, and constructs a personalized greeting.

    Args:
        request: A file stream containing the HTTP request from the client.
        response: A file stream to write the HTTP response to.
    """

    try:
        # 1. Parse the request using cgi.FieldStorage to handle form data safely.
        form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST' if request.readable() else 'GET'})

        # 2. Validate the request method.
        method = form.environ.get('REQUEST_METHOD', 'GET').upper()
        if method == 'POST':
            username = form.getvalue("username", "")
            csrf_token = form.getvalue("csrf_token", "") # Get CSRF token from the form
        else:
            username = form.getvalue("username", "")  # Or handle GET differently
            csrf_token = None # No CSRF token for GET requests

        # 3. Input Validation and Sanitization: Strict allowlist for username.
        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
        MAX_USERNAME_LENGTH = 50
        sanitized_username = "".join(c for c in username if c in allowed_chars)[:MAX_USERNAME_LENGTH]

        # 4. HTML Escaping: Escape the username to prevent XSS.
        escaped_username = html.escape(sanitized_username)

        # 5. Session Management (HttpOnly cookie - example)
        session_id = get_session_id(request)  # Get existing session or create a new one
        if not session_id:
            session_id = secrets.token_hex(16)  # Generate a random session ID
            # Store session_id on the server-side (e.g., in a database or in-memory cache)
            session_storage[session_id] = {}  # Initialize session data
            logging.info(f"New session created: {session_id}")

        # 6. CSRF Validation (if POST request)
        if method == 'POST':
            if not csrf_token or not validate_csrf_token(session_id, csrf_token):
                logging.warning(f"CSRF validation failed for session: {session_id}")
                response.write(f"HTTP/1.1 403 Forbidden\r\n".encode("utf-8"))
                response.write(f"Content-Type: text/plain; charset=utf-8\r\n".encode("utf-8"))
                response.write(b"\r\n")
                response.write(b"CSRF validation failed".encode("utf-8"))
                return  # Stop processing the request

        # 7. Generate a new CSRF token for the next request
        new_csrf_token = generate_csrf_token()
        store_csrf_token_in_session(session_id, new_csrf_token)

        # 8. Construct the response. Set Content-Type and encoding.
        response_body = f"<html><body><h1>Hello, {escaped_username}!</h1>"
        response_body += f"<form method='POST'><input type='hidden' name='csrf_token' value='{new_csrf_token}'><input type='text' name='username'><input type='submit' value='Submit'></form>" # Include CSRF token in the form
        response_body += "</body></html>"

        response_headers = [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),  # Prevent caching
            ("X-Content-Type-Options", "nosniff"),  # Prevent MIME sniffing
            ("X-Frame-Options", "DENY"),  # Prevent clickjacking
            ("Content-Security-Policy", "default-src 'self'"),  # Mitigate XSS
        ]

        cookie = http.cookies.SimpleCookie()
        cookie["sessionid"] = session_id
        cookie["sessionid"]["httponly"] = True
        cookie["sessionid"]["samesite"] = "Strict"  # Recommended for security
        cookie["sessionid"]["secure"] = os.environ.get("HTTPS", "false").lower() == "true" # Ensure secure flag is set only in HTTPS
        response_headers.append(("Set-Cookie", cookie.output(header='').strip()))

        # 9. Write the response headers and body to the response stream.
        response.write(f"HTTP/1.1 200 OK\r\n".encode("utf-8"))
        for header, value in response_headers:
            response.write(f"{header}: {value}\r\n".encode("utf-8"))
        response.write("\r\n".encode("utf-8"))  # End of headers
        response.write(response_body.encode("utf-8"))

        logging.info(f"Request processed successfully for username: {sanitized_username}, session: {session_id}")

    except Exception as e:
        logging.exception("An error occurred while processing the request:")
        response.write(f"HTTP/1.1 500 Internal Server Error\r\n".encode("utf-8"))
        response.write(f"Content-Type: text/plain; charset=utf-8\r\n".encode("utf-8"))
        response.write(b"\r\n")
        response.write(f"An error occurred. Please check the logs.".encode("utf-8")) # Generic error message for the user

def get_session_id(request):
    """Retrieves the session ID from the request cookies."""
    cookie = http.cookies.SimpleCookie(request.headers.get("Cookie"))
    if "sessionid" in cookie:
        session_id = cookie["sessionid"].value
        if session_id in session_storage: # Validate that the session exists
            return session_id
        else:
            logging.warning(f"Invalid session ID found in cookie: {session_id}")
            return None
    else:
        return None

def generate_csrf_token():
    return secrets.token_hex(16)

def validate_csrf_token(session_id, csrf_token):
    stored_csrf_token = get_csrf_token_from_session(session_id)

    if stored_csrf_token and csrf_token == stored_csrf_token:
        return True
    else:
        return False

def get_csrf_token_from_session(session_id):
    if session_id in session_storage and "csrf_token" in session_storage[session_id]:
        return session_storage[session_id]["csrf_token"]
    else:
        return None

def store_csrf_token_in_session(session_id, csrf_token):
    if session_id in session_storage:
        session_storage[session_id]["csrf_token"] = csrf_token
    else:
        logging.error(f"Session ID not found when storing CSRF token: {session_id}")

# Example usage (replace with your actual server implementation)
class MockRequest:
    def __init__(self, method, data=None, headers=None):
        self.method = method
        self.data = data
        self.headers = headers or {}

    def readable(self):
        return self.method == 'POST'

    @property
    def environ(self):
        return {'REQUEST_METHOD': self.method}

class MockResponse:
    def __init__(self):
        self.data = b""
        self.headers_list = []

    def write(self, data):
        if isinstance(data, str):
            self.data += data.encode("utf-8")
        else:
            self.data += data

    def getvalue(self):
        return self.data

    @property
    def headers(self):
        return self.headers_list

# Example POST request
request = MockRequest(method='POST', data={'username': 'testuser', 'csrf_token': 'dummy_csrf_token'}, headers={'Cookie': 'sessionid=some_session_id'})
response = MockResponse()
http_hello_page(request, response)
print(response.getvalue().decode("utf-8"))

# Example GET request
request = MockRequest(method='GET', data={'username': 'testuser'}, headers={'Cookie': 'sessionid=some_session_id'})
response = MockResponse()
http_hello_page(request, response)
print(response.getvalue().decode("utf-8"))

