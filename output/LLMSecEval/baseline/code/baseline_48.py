import http.server
import socketserver
import html
import cgi
import os
import ssl  # For HTTPS

# --- Security Considerations ---
# 1. Input Sanitization:  Crucially important to prevent XSS.  The `html.escape()` function is used to sanitize the username.
# 2. Output Encoding:  Ensure the output is properly encoded (UTF-8 is a good default).
# 3. Path Traversal:  If you were to use the username to access files, you'd need to prevent path traversal attacks (e.g., "username = '../etc/passwd'").  This example doesn't do that, but it's a common vulnerability.
# 4. Rate Limiting:  Consider rate limiting to prevent denial-of-service attacks.  This is not implemented here but is important in production.
# 5. HTTPS:  Using HTTPS is essential for protecting sensitive data (like usernames) in transit.  The example includes HTTPS setup.
# 6. Error Handling:  Robust error handling is important to prevent information leakage and unexpected behavior.
# 7. Logging:  Log requests and errors for auditing and debugging.  Be careful not to log sensitive information.
# 8. Security Headers:  Set security headers (e.g., Content-Security-Policy, X-Frame-Options, X-XSS-Protection) to mitigate various attacks.  This is not implemented here but is important in production.
# 9. Avoid `eval()` and `exec()`:  Never use `eval()` or `exec()` with user-supplied input, as this can lead to arbitrary code execution.
# 10. Update Dependencies: Keep your Python interpreter and all libraries up to date to patch security vulnerabilities.

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/hello':
            self.http_hello_page()
        else:
            super().do_GET()  # Handle other requests normally

    def do_POST(self):
        if self.path == '/hello':
            self.http_hello_page()
        else:
            super().do_POST()

    def http_hello_page(self):
        """Handles the /hello endpoint."""

        # Read the request body (username)
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            username_bytes = self.rfile.read(content_length)
            try:
                username = username_bytes.decode('utf-8')
            except UnicodeDecodeError:
                self.send_response(400)  # Bad Request
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"Invalid username encoding.  Use UTF-8.")
                return
        else:
            username = "Guest"  # Default username if no body is provided

        # Sanitize the username to prevent XSS
        sanitized_username = html.escape(username)

        # Construct the response body (HTML page)
        outputbuf = f"""<!DOCTYPE html>
        <html>
        <head>
            <title>Hello Page</title>
        </head>
        <body>
            <h1>Hello, {sanitized_username}!</h1>
            <p>Welcome to the secure hello page.</p>
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
            print("Client disconnected before response could be sent.")
        except Exception as e:
            print(f"Error writing to response stream: {e}")

        # The server automatically closes the response stream after the handler returns.
        # No need to explicitly close it.
        print(f"Served /hello to {self.client_address[0]} with username: {username}")


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
    # Generate self-signed certificates for HTTPS (for testing purposes only!)
    # In a production environment, use certificates from a trusted CA.
    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        print("Generating self-signed certificates (for testing only!).  DO NOT USE IN PRODUCTION.")
        os.system("openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -subj '/CN=localhost'")

    run_server(port=8000, use_https=True)  # Enable HTTPS by default

