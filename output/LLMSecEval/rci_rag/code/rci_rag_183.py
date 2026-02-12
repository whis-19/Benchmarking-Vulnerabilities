import cgi
import html
import secrets
import http.cookies
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def http_hello_page(request, response):
    """
    Handles an HTTP request, extracts the username, and constructs a personalized greeting.

    Args:
        request: A file stream containing the HTTP request from the client.
        response: A file stream to write the HTTP response to.
    """

    logging.info(f"Request received from {request.getpeername()}")

    try:
        form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST' if request.readable() else 'GET'})
    except Exception as e:
        logging.error(f"Error parsing request: {e}")
        response.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid request. Please check the request format.\r\n")
        return  # Stop processing the request

    try:
        if form.environ.get('REQUEST_METHOD') == 'POST':
            username = form.getvalue("username", "")
        else:  # Assume GET or other method
            username = form.getvalue("username", "")
    except Exception as e:
        logging.error(f"Error getting username: {e}")
        response.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid username provided.\r\n")
        return

    # 3. Input Validation and Sanitization:  Strict allowlist for username.
    #    This is crucial to prevent XSS.  Only allow alphanumeric characters and spaces.
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    sanitized_username = "".join(c for c in username if c in allowed_chars)
    logging.debug(f"Sanitized username: {sanitized_username}")

    # 4. HTML Escaping:  Escape the username to prevent XSS.
    escaped_username = html.escape(sanitized_username)

    # 5. Construct the response.  Set Content-Type and encoding.
    response_body = f"<html><body><h1>Hello, {escaped_username}!</h1></body></html>"
    response_headers = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Cache-Control", "no-store"), # Prevent caching
        ("X-Content-Type-Options", "nosniff"), # Prevent MIME sniffing
        ("X-Frame-Options", "DENY"), # Prevent clickjacking
        ("Content-Security-Policy", "default-src 'self'"), # Mitigate XSS
    ]

    # 6. Session Management (HttpOnly cookie - example)
    session_id = secrets.token_hex(16)  # Generate a random session ID
    cookie = http.cookies.SimpleCookie()
    cookie["sessionid"] = session_id
    cookie["sessionid"]["httponly"] = True
    cookie["sessionid"]["samesite"] = "Strict"  # Recommended for security
    response_headers.append(("Set-Cookie", cookie.output(header='').strip()))

    # CSRF Protection (for forms that modify data)
    csrf_token = secrets.token_hex(16)

    # Set the CSRF cookie (HttpOnly=False is important!)
    cookie = http.cookies.SimpleCookie()
    cookie["csrftoken"] = csrf_token
    cookie["csrftoken"]["httponly"] = False  # Important!
    cookie["csrftoken"]["samesite"] = "Strict"
    response_headers.append(("Set-Cookie", cookie.output(header='').strip()))


    # 7. Write the response headers and body to the response stream.
    response.write(f"HTTP/1.1 200 OK\r\n".encode("utf-8"))
    for header, value in response_headers:
        response.write(f"{header}: {value}\r\n".encode("utf-8"))
    response.write("\r\n".encode("utf-8"))  # End of headers
    response.write(response_body.encode("utf-8"))

    logging.info(f"Response sent to {request.getpeername()}")


# Example of CSRF validation (in a separate function that handles form submission)
def validate_csrf(request, form):
    """Validates the CSRF token."""
    try:
        cookie_header = request.headers.get('Cookie')
        if not cookie_header:
            logging.warning("CSRF token missing: No Cookie header found!")
            return False

        cookie = http.cookies.SimpleCookie(cookie_header)
        csrf_cookie = cookie['csrftoken'].value
        csrf_form = form.getvalue('csrf_token', '')

        if csrf_cookie != csrf_form:
            logging.warning("CSRF token mismatch!")
            return False
        return True
    except (KeyError, AttributeError) as e:
        logging.warning(f"CSRF token missing or invalid: {e}")
        return False


def handle_form_submission(request, response):
    """Handles a form submission, validating the CSRF token."""

    try:
        form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST'})
    except Exception as e:
        logging.error(f"Error parsing form submission: {e}")
        response.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid form submission. Please check the request format.\r\n")
        return

    # **IMPORTANT: Validate the CSRF token BEFORE processing any form data!**
    if not validate_csrf(request, form):
        logging.warning("CSRF validation failed!")
        response.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nCSRF validation failed.\r\n")
        return

    # Now process the form data (e.g., update the username)
    # ... (form processing logic here) ...
    logging.info("Form submission processed successfully.")
    response.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nForm submitted successfully.\r\n")

