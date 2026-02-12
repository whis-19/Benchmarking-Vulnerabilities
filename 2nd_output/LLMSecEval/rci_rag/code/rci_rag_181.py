import cgi
import html
import os
import secrets
import logging
from http import cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import time
import redis
import json

# --- Configuration ---
ALLOWED_USERNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
SESSION_COOKIE_NAME = "sessionid"
NONCE_LENGTH = 16  # Length of the nonce in bytes
MAX_USERNAME_LENGTH = 32
RATE_LIMIT_SECONDS = 1  # Minimum time between requests from the same IP
SESSION_EXPIRY_SECONDS = 1800  # 30 minutes
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
# --- End Configuration ---

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Redis Connection ---
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)


def generate_nonce():
    """Generates a cryptographically secure random nonce."""
    return secrets.token_hex(NONCE_LENGTH)


def is_valid_username(username):
    """Validates the username against an allowlist of characters."""
    if not username:
        return False
    if len(username) > MAX_USERNAME_LENGTH:
        return False
    return all(char in ALLOWED_USERNAME_CHARS for char in username)


def get_session_data(session_id):
    """Retrieves session data from Redis."""
    try:
        session_data = redis_client.get(session_id)
        if session_data:
            return json.loads(session_data.decode('utf-8'))  # Decode from bytes to string
        return None
    except redis.exceptions.ConnectionError as e:
        logging.error(f"Redis connection error: {e}")
        return None


def set_session_data(session_id, data):
    """Sets session data in Redis with expiry."""
    try:
        redis_client.setex(session_id, SESSION_EXPIRY_SECONDS, json.dumps(data))  # Encode to JSON string
    except redis.exceptions.ConnectionError as e:
        logging.error(f"Redis connection error: {e}")


def delete_session_data(session_id):
    """Deletes session data from Redis."""
    try:
        redis_client.delete(session_id)
    except redis.exceptions.ConnectionError as e:
        logging.error(f"Redis connection error: {e}")


def get_session_id(handler):
    """Retrieves the session ID from the cookie, or generates a new one."""
    cookie = handler.cookies.get(SESSION_COOKIE_NAME)
    if cookie:
        session_id = cookie.value
        # Check if the session exists in Redis
        if get_session_data(session_id):
            return session_id
        else:
            logging.warning(f"Invalid session ID: {session_id}.  Generating a new one.")
    # Generate a new session ID
    session_id = secrets.token_hex(16)
    return session_id


def double_submit_cookie_check(handler, form_nonce, session_id):
    """Checks for double-submitted cookie."""
    session_data = get_session_data(session_id)

    if not session_data:
        logging.warning(f"Session ID {session_id} not found.")
        return False

    cookie_nonce = session_data.get("nonce")

    if not cookie_nonce:
        logging.warning(f"Nonce not found in session {session_id}.")
        return False

    if cookie_nonce != form_nonce:
        logging.warning(f"CSRF detected for session {session_id}.  Form nonce: {form_nonce}, Cookie nonce: {cookie_nonce}")
        return False

    return True


class MyHTTPRequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cookies = cookies.SimpleCookie()

    def send_html_response(self, content, status_code=200):
        """Sends an HTML response with proper headers."""
        self.send_response(status_code)
        self.send_header("Content-type", "text/html; charset=utf-8")  # Specify encoding
        self.send_header("X-Content-Type-Options", "nosniff")  # Prevent MIME sniffing
        self.send_header("X-Frame-Options", "SAMEORIGIN")  # Prevent clickjacking
        self.send_header("Content-Security-Policy", "default-src 'self'")  # Mitigate XSS
        if self.cookies:
            for morsel in self.cookies.values():
                self.send_header("Set-Cookie", morsel.OutputString())
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def check_rate_limit(self):
        """Checks if the request is within the rate limit."""
        client_ip = self.client_address[0]
        now = time.time()

        try:
            last_request_time = redis_client.get(f"rate_limit:{client_ip}")
            if last_request_time:
                last_request_time = float(last_request_time.decode('utf-8'))
                time_since_last_request = now - last_request_time
                if time_since_last_request < RATE_LIMIT_SECONDS:
                    logging.warning(f"Rate limit exceeded for IP: {client_ip}")
                    self.send_html_response("Too many requests. Please wait.", status_code=429)  # 429 Too Many Requests
                    return False

            redis_client.set(f"rate_limit:{client_ip}", now, ex=RATE_LIMIT_SECONDS * 2)  # Expire after double the rate limit
            return True
        except redis.exceptions.ConnectionError as e:
            logging.error(f"Redis connection error: {e}")
            self.send_html_response("Service Unavailable", status_code=503)
            return False

    def do_GET(self):
        """Handles GET requests."""
        if not self.check_rate_limit():
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == "/hello":
            self.http_hello_page()
        elif path == "/":
            session_id = get_session_id(self)
            nonce = generate_nonce()

            # Store the nonce in the session (using Redis)
            set_session_data(session_id, {"nonce": nonce})

            # Set the cookie with the session ID
            self.cookies[SESSION_COOKIE_NAME] = session_id
            self.cookies[SESSION_COOKIE_NAME]["httponly"] = True
            self.cookies[SESSION_COOKIE_NAME]["samesite"] = "Strict"
            # Add secure attribute if using HTTPS
            # if self.protocol_version == "HTTPS/1.0" or self.protocol_version == "HTTPS/1.1":
            #     self.cookies[SESSION_COOKIE_NAME]["secure"] = True

            self.send_html_response(
                f"""
                <html>
                <head><title>Hello Form</title></head>
                <body>
                    <form action="/hello" method="POST">
                        Username: <input type="text" name="username"><br>
                        <input type="hidden" name="nonce" value="{nonce}">
                        <input type="submit" value="Submit">
                    </form>
                </body>
                </html>
                """
            )
            logging.info(f"Generated new session {session_id} and nonce for IP: {self.client_address[0]}")

        else:
            self.send_error_page(404, "Not Found")

    def do_POST(self):
        """Handles POST requests."""
        if not self.check_rate_limit():
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == "/hello":
            self.http_hello_page()
        else:
            self.send_error_page(404, "Not Found")

    def http_hello_page(self):
        """Handles the /hello URL request."""
        form = cgi.FieldStorage(
            fp=self.rfile, headers=self.headers, environ={"REQUEST_METHOD": "POST"}
        )

        username = form.getvalue("username", "")
        form_nonce = form.getvalue("nonce", "")

        # --- Input Validation ---
        if not isinstance(username, str):
            self.send_error_page(400, "Invalid username format.")
            return

        if not is_valid_username(username):
            self.send_error_page(400, "Invalid username.  Only alphanumeric characters and underscores are allowed.")
            return

        # --- CSRF Protection: Double-Submit Cookie Check ---
        session_id = get_session_id(self)
        if not double_submit_cookie_check(self, form_nonce, session_id):
            self.send_error_page(403, "CSRF detected. Invalid nonce.")
            return

        # --- XSS Prevention: Escape the username ---
        escaped_username = html.escape(username)

        # --- Construct the HTML response ---
        outputbuf = f"""
        <html>
        <head><title>Hello Page</title></head>
        <body>
            <h1>Hello, {escaped_username}!</h1>
            <p>Welcome to the secure hello page.</p>
        </body>
        </html>
        """

        self.send_html_response(outputbuf)
        logging.info(f"Hello page accessed successfully for username: {username}, IP: {self.client_address[0]}")

    def send_error_page(self, status_code, message):
        """Sends a custom error page."""
        self.send_response(status_code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        escaped_message = html.escape(message)  # Escape the message
        error_html = f"""
        <html>
        <head><title>Error {status_code}</title></head>
        <body>
            <h1>Error {status_code}</h1>
            <p>{escaped_message}</p>
        </body>
        </html>
        """
        self.wfile.write(error_html.encode("utf-8"))
        logging.error(f"Error {status_code}: {message}, IP: {self.client_address[0]}")


def run(server_class=HTTPServer, handler_class=MyHTTPRequestHandler, port=8000):
    """Runs the server."""
    server_address = ("", port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting server on port {port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("Stopping server")


if __name__ == "__main__":
    run()

