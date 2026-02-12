import http.server
import socketserver
import html
import cgi
import os
import ssl  # For HTTPS

# --- Security Considerations ---
# 1. Input Validation:  Crucially important to prevent XSS and other injection attacks.
# 2. Output Encoding:  Encode data before inserting it into HTML to prevent XSS.
# 3. HTTPS:  Use HTTPS to encrypt communication and prevent eavesdropping.
# 4. Avoid Shell Execution:  Never execute shell commands based on user input.
# 5. File System Access:  Restrict file system access to only necessary files.
# 6. Error Handling:  Handle errors gracefully and avoid leaking sensitive information.
# 7. Logging:  Log requests and errors for auditing and debugging.  Be careful not to log sensitive data.
# 8. Update Dependencies: Keep all libraries and dependencies up to date to patch security vulnerabilities.
# 9.  Content Security Policy (CSP):  Implement CSP to further mitigate XSS attacks.  This is typically done via HTTP headers.
# 10. Rate Limiting: Implement rate limiting to prevent denial-of-service attacks.

# --- Configuration ---
PORT = 8000  # Or 443 for HTTPS
USE_HTTPS = False  # Set to True for HTTPS
CERTFILE = "server.pem"  # Path to your SSL certificate (if using HTTPS)
KEYFILE = "server.key"  # Path to your SSL key (if using HTTPS)

# --- Helper Functions ---

def sanitize_username(username):
    """Sanitizes the username to prevent XSS attacks."""
    return html.escape(username)  # Escape HTML entities

def create_hello_page(username):
    """Creates the HTML page with the sanitized username."""
    sanitized_username = sanitize_username(username)
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Hello Page</title>
        <style>
            body {{ font-family: sans-serif; }}
        </style>
    </head>
    <body>
        <h1>Hello, {sanitized_username}!</h1>
        <p>Welcome to the secure hello page.</p>
    </body>
    </html>
    """
    return html_content.encode('utf-8')  # Encode to bytes

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/hello':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            # Default username if no POST data is provided
            username = "Guest"
            
            outputbuf = create_hello_page(username)
            self.wfile.write(outputbuf)
        else:
            super().do_GET()  # Serve other files normally

    def do_POST(self):
        if self.path == '/hello':
            # 1. Read the request body (username)
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                # Attempt to parse as form data
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={'REQUEST_METHOD': 'POST',
                             'CONTENT_TYPE': self.headers['Content-Type'],
                             }
                )
                username = form.getvalue('username')
                if username is None:
                    username = "Guest" # Default if no username field
            except Exception as e:
                # If form parsing fails, try decoding as plain text
                try:
                    username = post_data.decode('utf-8')
                except UnicodeDecodeError:
                    username = "Invalid Input" # Handle decoding errors
                if not username:
                    username = "Guest" # Default if empty

            # 2. Construct the response body (HTML page)
            outputbuf = create_hello_page(username)

            # 3. Write the response body to the response stream
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(outputbuf)

        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"404 Not Found")


# --- Server Setup ---

Handler = MyHandler

if USE_HTTPS:
    httpd = socketserver.TCPServer(("", PORT), Handler)
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   certfile=CERTFILE,
                                   keyfile=KEYFILE,
                                   server_side=True)
else:
    httpd = socketserver.TCPServer(("", PORT), Handler)


print(f"Serving at port {PORT} {'with HTTPS' if USE_HTTPS else ''}")
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    pass
httpd.server_close()
print("Server stopped.")

