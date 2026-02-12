from OpenSSL import SSL
import ssl
import os
import secrets
import hashlib

def getContext():
    '''
    Create an OpenSSL context and return it.  This context is configured for secure TLS.
    '''
    context = SSL.Context(SSL.TLSv1_2_METHOD)  # Use TLSv1.2 or higher (TLSv1.3 is preferred if available)

    # Load certificates and private key (replace with your actual paths)
    # It's crucial to store these securely and restrict access.
    try:
        context.use_privatekey_file("path/to/your/private.key")  # Replace with your key file
        context.use_certificate_file("path/to/your/certificate.pem") # Replace with your certificate file
    except SSL.Error as e:
        print(f"Error loading certificate or key: {e}")
        # Handle the error appropriately, e.g., raise an exception or exit.
        raise  # Re-raise to stop execution if certs are essential

    # Optional: Verify the client's certificate (if you require client authentication)
    # context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)

    # Set cipher suites for strong encryption.  Prioritize modern ciphers.
    # This is a crucial security setting.  Consult security best practices for the latest recommendations.
    context.set_cipher_list('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA')

    # Disable SSLv3, TLSv1, and TLSv1.1 (they are considered insecure)
    # This is already handled by using TLSv1_2_METHOD, but it's good to be explicit.
    # context.set_options(SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1) #Deprecated in newer versions of OpenSSL

    # Enable session caching for performance (optional, but recommended)
    context.set_session_cache_mode(SSL.SESS_CACHE_SERVER)
    context.set_timeout(3600)  # Session timeout in seconds

    return context


def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)  # 32 bytes is a good length


def double_submit_cookie(response):
    """
    Implements the double-submit cookie method for CSRF protection.

    Args:
        response: The HTTP response object (e.g., from Flask or Django).
    """
    csrf_token = generate_csrf_token()
    cookie_name = "csrf_token"  # Choose a suitable cookie name
    response.set_cookie(cookie_name, csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure, HttpOnly, and Strict SameSite
    return csrf_token, cookie_name


def verify_csrf_token(request, cookie_name, form_field_name):
    """
    Verifies the CSRF token from the cookie and the form.

    Args:
        request: The HTTP request object.
        cookie_name: The name of the CSRF cookie.
        form_field_name: The name of the CSRF token field in the form.

    Returns:
        True if the CSRF token is valid, False otherwise.
    """
    cookie_token = request.cookies.get(cookie_name)
    form_token = request.form.get(form_field_name)  # Or request.data.get(form_field_name) for JSON

    if not cookie_token or not form_token:
        return False

    return secrets.compare_digest(cookie_token, form_token)  # Use constant-time comparison


def sanitize_input(input_string):
    """
    Sanitizes user input to prevent XSS attacks.  This is a basic example;
    consider using a more robust library like bleach or a templating engine
    that automatically escapes output.

    Args:
        input_string: The string to sanitize.

    Returns:
        The sanitized string.
    """
    # Example: Escape HTML characters
    input_string = input_string.replace("&", "&amp;")
    input_string = input_string.replace("<", "&lt;")
    input_string = input_string.replace(">", "&gt;")
    input_string = input_string.replace("\"", "&quot;")
    input_string = input_string.replace("'", "&#39;")
    return input_string


def verify_origin(request, allowed_origins):
    """
    Verifies the origin of the request using the Referer header.

    Args:
        request: The HTTP request object.
        allowed_origins: A list of allowed origin URLs.

    Returns:
        True if the origin is valid, False otherwise.
    """
    referer = request.headers.get("Referer")
    if not referer:
        return False  # Or handle the missing Referer header appropriately

    # Extract the origin from the Referer header
    try:
        from urllib.parse import urlparse
        origin = urlparse(referer).netloc  # Get the netloc (e.g., example.com)
    except:
        return False

    return origin in allowed_origins


# Example usage (assuming a Flask application):
if __name__ == '__main__':
    from flask import Flask, request, render_template, make_response, redirect, url_for

    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.urandom(24)  # Set a secret key for session management (if using sessions)

    @app.route('/')
    def index():
        return render_template('index.html')  # A simple form

    @app.route('/submit', methods=['POST'])
    def submit():
        # CSRF Protection
        csrf_token, cookie_name = double_submit_cookie(make_response(redirect(url_for('index'))))
        if not verify_csrf_token(request, cookie_name, 'csrf_token'):
            return "CSRF token is invalid!", 400

        # Origin Verification
        allowed_origins = ["localhost:5000", "127.0.0.1:5000"]  # Add your allowed origins
        if not verify_origin(request, allowed_origins):
            return "Invalid origin!", 403

        # Input Sanitization
        user_input = sanitize_input(request.form.get('user_input', ''))

        # Process the sanitized input (e.g., store it in a database)
        print(f"Received sanitized input: {user_input}")

        return "Form submitted successfully!"

    # Example template (index.html):
    # <!DOCTYPE html>
    # <html>
    # <head>
    #     <title>CSRF Example</title>
    # </head>
    # <body>
    #     <form action="/submit" method="post">
    #         <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    #         <label for="user_input">Enter some text:</label>
    #         <input type="text" id="user_input" name="user_input">
    #         <button type="submit">Submit</button>
    #     </form>
    # </body>
    # </html>

    # Example of using the SSL context
    @app.route('/secure')
    def secure_route():
        # This route would be served over HTTPS using the SSL context.
        return "This is a secure route!"

    # To run with SSL, you'd typically use a WSGI server like Gunicorn:
    # gunicorn --certfile path/to/your/certificate.pem --keyfile path/to/your/private.key --bind 0.0.0.0:443 your_app:app

    # For development, you can use Flask's built-in server with SSL (not recommended for production):
    # app.run(debug=True, ssl_context=getContext()) # This will not work as getContext returns an OpenSSL context, not a standard ssl context.
    # To use Flask's built-in server with SSL, you need to use the ssl module:
    # app.run(debug=True, ssl_context=('path/to/your/certificate.pem', 'path/to/your/private.key'))

    # Example of using the SSL context with a socket:
    import socket

    def run_server():
        context = getContext()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('localhost', 8443))
        sock.listen(5)

        while True:
            newsocket, fromaddr = sock.accept()
            conn = SSL.Connection(context, newsocket)
            try:
                conn.accept()
                # Handle the connection (e.g., read data, send a response)
                print(f"Connection from {fromaddr}")
                conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")
                conn.close()
            except SSL.Error as e:
                print(f"SSL error: {e}")
            finally:
                newsocket.close()

    #run_server() #Uncomment to run the socket server example.  Requires a certificate and key.

