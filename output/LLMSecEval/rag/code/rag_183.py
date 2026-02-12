import cgi
import html
import secrets
import http.cookies
from urllib.parse import urlparse, urlunparse

def http_hello_page(request, response):
    """
    Handles an HTTP request, extracts the username, and constructs a personalized greeting.

    Args:
        request: A file stream containing the HTTP request from the client.
        response: A file stream to write the HTTP response to.
    """

    # 1. Parse the request using cgi.FieldStorage for security.  This handles various content types.
    form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST' if request.method == 'POST' else 'GET'}, keep_blank_values=True)

    # 2. Validate the request method.  Only allow GET or POST.  If POST, require a nonce.
    if request.method not in ('GET', 'POST'):
        response.write(b"HTTP/1.1 405 Method Not Allowed\r\n")
        response.write(b"Content-Type: text/plain\r\n")
        response.write(b"\r\n")
        response.write(b"Method Not Allowed\r\n")
        return

    # 3.  Handle Nonce (CSRF protection) if it's a POST request.
    nonce = None
    if request.method == 'POST':
        nonce = form.getvalue('nonce')
        if not nonce or not validate_nonce(nonce):
            response.write(b"HTTP/1.1 403 Forbidden\r\n")
            response.write(b"Content-Type: text/plain\r\n")
            response.write(b"\r\n")
            response.write(b"CSRF Attack Detected\r\n")
            return

    # 4. Extract and Validate Username
    username = form.getvalue('username')

    if not username:
        username = "Guest"  # Default username

    # 5.  Sanitize the username using an allowlist.  Only allow alphanumeric characters and spaces.
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    safe_username = ''.join(c for c in username if c in allowed_chars)

    # 6.  HTML Escape the username to prevent XSS.
    escaped_username = html.escape(safe_username)

    # 7. Construct the response.
    greeting = f"Hello {escaped_username}!".encode('utf-8')

    # 8. Set HTTP Headers (including Content-Type and encoding)
    response.write(b"HTTP/1.1 200 OK\r\n")
    response.write(b"Content-Type: text/html; charset=utf-8\r\n")
    response.write(b"X-Frame-Options: SAMEORIGIN\r\n")  # Prevent Clickjacking
    response.write(b"X-Content-Type-Options: nosniff\r\n") # Prevent MIME sniffing
    response.write(b"Content-Security-Policy: default-src 'self'\r\n") # Mitigate XSS
    response.write(b"Set-Cookie: sessionid=" + generate_session_id().encode('utf-8') + b"; HttpOnly; Secure\r\n") # HttpOnly cookie
    response.write(b"\r\n")  # End of headers

    # 9. Write the response body.
    response.write(greeting)

def generate_nonce():
    """Generates a unique and unpredictable nonce."""
    return secrets.token_hex(16)

def validate_nonce(nonce):
    """Validates a nonce against a stored list of valid nonces.  
       This is a placeholder.  In a real application, you would store
       valid nonces (e.g., in a session) and remove them after use.
    """
    # In a real application, you would check if the nonce is in a list of valid nonces
    # and remove it from the list after validation.
    # This is a simplified example for demonstration purposes.
    # WARNING: This is NOT secure in a production environment.
    return True  # Replace with actual validation logic

def generate_session_id():
    """Generates a unique session ID."""
    return secrets.token_hex(16)

def is_valid_url(url):
    """
    Validates a URL to prevent open redirects.  This is a basic example.
    A more robust implementation would use a whitelist of allowed domains.
    """
    try:
        result = urlparse(url)
        # Check if the scheme is HTTP or HTTPS
        if result.scheme not in ('http', 'https'):
            return False
        # Check if the netloc (domain) is in a whitelist of allowed domains.
        # For example:
        # allowed_domains = ['example.com', 'safe-domain.net']
        # if result.netloc not in allowed_domains:
        #     return False
        return True
    except:
        return False

def sanitize_url(url):
    """
    Sanitizes a URL to prevent injection attacks.  This is a basic example.
    A more robust implementation would use a whitelist of allowed schemes and domains.
    """
    if not is_valid_url(url):
        return None  # Or a default safe URL

    # Reconstruct the URL to ensure it's well-formed.
    parsed_url = urlparse(url)
    return urlunparse(parsed_url)

# Example usage (for testing - replace with your actual web server framework)
if __name__ == '__main__':
    import io

    # Simulate a GET request
    request_data_get = io.BytesIO(b"username=TestUser")
    request_data_get.method = 'GET'
    response_buffer = io.BytesIO()
    http_hello_page(request_data_get, response_buffer)
    print("GET Response:", response_buffer.getvalue().decode('utf-8'))

    # Simulate a POST request with a nonce
    nonce_value = generate_nonce()
    post_data = f"username=PostUser&nonce={nonce_value}".encode('utf-8')
    request_data_post = io.BytesIO(post_data)
    request_data_post.method = 'POST'
    response_buffer = io.BytesIO()
    http_hello_page(request_data_post, response_buffer)
    print("POST Response:", response_buffer.getvalue().decode('utf-8'))

    # Simulate a POST request with an invalid nonce
    post_data_invalid_nonce = b"username=PostUser&nonce=invalid_nonce"
    request_data_invalid_nonce = io.BytesIO(post_data_invalid_nonce)
    request_data_invalid_nonce.method = 'POST'
    response_buffer = io.BytesIO()
    http_hello_page(request_data_invalid_nonce, response_buffer)
    print("POST Response (Invalid Nonce):", response_buffer.getvalue().decode('utf-8'))

