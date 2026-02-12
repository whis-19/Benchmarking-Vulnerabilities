import http.server
import socketserver
import html
import cgi
import os
import ssl  # For HTTPS
import re  # For input validation
import logging  # For logging
import secrets  # For CSRF tokens
import time  # For basic rate limiting
import hashlib # For hashing usernames

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RateLimiter:
    def __init__(self, rate, per):
        self.rate = rate
        self.per = per
        self.allowance = rate
        self.last_check = time.time()

    def is_allowed(self):
        """Checks if a request is allowed based on the rate limit."""
        now = time.time()
        time_passed = now - self.last_check
        self.last_check = now

        self.allowance += time_passed * (self.rate / self.per)
        if self.allowance > self.rate:
            self.allowance = self.rate  # Never exceed the maximum

        if self.allowance < 1.0:
            return False  # Rate limit exceeded
        else:
            self.allowance -= 1.0
            return True  # Request allowed

# Example usage:  Limit to 10 requests per minute
rate_limiter = RateLimiter(rate=10, per=60)


class MyHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = {}  # In-memory session (NOT for production)

    def generate_csrf_token(self):
        """Generates a CSRF token for the session."""
        token = secrets.token_hex(16)
        self.session['csrf_token'] = token
        return token

    def check_csrf_token(self, token):
        """Checks if the CSRF token is valid."""
        return token == self.session.get('csrf_token')


    def end_headers(self):
        """Set security headers."""
        self.send_header('Content-Security-Policy', "default-src 'self'")
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        self.send_header('Access-Control-Allow-Origin', '*')  # DEVELOPMENT ONLY!  Restrict in production.
        # In production, replace '*' with the specific origin(s) you want to allow:
        # self.send_header('Access-Control-Allow-Origin', 'https://example.com')
        super().end_headers()

    def do_OPTIONS(self):
        """Handles preflight OPTIONS requests for CORS."""
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')  # DEVELOPMENT ONLY!
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token')  # Add any custom headers you use
        self.end_headers()


    def do_GET(self):
        if self.path.startswith('/hello'):
            self.http_hello_page()
        else:
            super().do_GET()  # Handle other requests normally

    def do_POST(self):
        if self.path == '/hello':
            self.http_hello_page()
        else:
            super().do_POST()

    def sanitize_username(self, username):
        """Sanitizes and validates the username."""
        username = username.strip()  # Remove leading/trailing whitespace
        username = re.sub(r"\s+", " ", username)  # Replace multiple spaces with a single space

        # Length limit
        if len(username) > 50:
            return "Username too long (max 50 characters)"

        # Allowed characters (alphanumeric and spaces, but no consecutive spaces)
        if not re.match(r"^[a-zA-Z0-9]+(?: [a-zA-Z0-9]+)*$", username):
            return "Invalid characters in username (only alphanumeric and spaces allowed, no consecutive spaces)"

        # HTML escape
        sanitized_username = html.escape(username)
        return sanitized_username

    def http_hello_page(self):
        """Handles the /hello endpoint with CSRF protection."""

        if not rate_limiter.is_allowed():
            self.send_response(429)  # Too Many Requests
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Too many requests. Please try again later.")
            return


        if self.command == 'POST':
            # Check CSRF token
            csrf_token = self.headers.get('X-CSRF-Token')  # Or from form data
            if not self.check_csrf_token(csrf_token):
                self.send_response(403)  # Forbidden
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"CSRF token invalid.")
                return

        # Read the request body (username)
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            try:
                username_bytes = self.rfile.read(content_length)
                username = username_bytes.decode('utf-8')
            except UnicodeDecodeError:
                self.send_response(400)  # Bad Request
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"Invalid username encoding.  Use UTF-8.")
                return
        else:
            username = "Guest"  # Default username if no body is provided

        # Sanitize and validate the username
        sanitized_username = self.sanitize_username(username)

        if "Invalid" in sanitized_username: # Check for validation errors
            self.send_response(400)  # Bad Request
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(sanitized_username.encode('utf-8'))
            return


        # Construct the response body (HTML page)
        csrf_token = self.generate_csrf_token()
        outputbuf = f"""<!DOCTYPE html>
        <html>
        <head>
            <title>Hello Page</title>
        </head>
        <body>
            <h1>Hello, {sanitized_username}!</h1>
            <p>Welcome to the secure hello page.</p>
            <form method="POST" action="/hello">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <input type="submit" value="Update Username">
            </form>
        </body>
        </html>"""

        # Write the response headers
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')  # Specify charset
        self.end_headers()

        # Write the response body
        try:
            self.wfile.write(outputbuf.encode('utf-8'))  # Encode to bytes
        except BrokenPipeError:
            # Handle the case where the client closes the connection prematurely
            logging.warning("Client disconnected before response could be sent.")
        except Exception as e:
            logging.exception(f"Error writing to response stream: {e}") # Log the full exception
            self.send_response(500)  # Internal Server Error
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"An unexpected error occurred. Please try again later.")  # Generic message


        # The server automatically closes the response stream after the handler returns.
        # No need to explicitly close it.
        # logging.info(f"Served /hello to {self.client_address[0]} with username: {sanitized_username}")
        hashed_username = hashlib.sha256(username.encode('utf-8')).hexdigest()
        logging.info(f"Served /hello to {self.client_address[0]} with hashed username: {hashed_username}")


def run_server(port=8000, use_https=False, certfile="cert.pem", keyfile="key.pem"):
    """Runs the HTTP or HTTPS server."""
    Handler = MyHandler

    with socketserver.TCPServer(("", port), Handler) as httpd:
        print(f"Serving at port {port}")

        if use_https:
            try:
                import ssl
                httpd.socket = ssl.wrap_socket(httpd.socket,
                                               certfile=certfile,
                                               keyfile=keyfile,
                                               server_side=True)
                print("Using HTTPS")
            except FileNotFoundError:
                print("HTTPS enabled, but certificate or key file not found.  Falling back to HTTP.")
                use_https = False # Fallback to HTTP
            except AttributeError:
                print("HTTPS requires Python 3.7 or higher. Falling back to HTTP.")
                use_https = False

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")


if __name__ == "__main__":
    # Generate self-signed certificates for HTTPS (for testing only!).  DO NOT USE IN PRODUCTION.
    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        print("Generating self-signed certificates (for testing only!).  DO NOT USE IN PRODUCTION.")
        os.system("openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -subj '/CN=localhost'")

    run_server(port=8000, use_https=True)  # Enable HTTPS by default

