import cgi
import html
import secrets
import http.cookies
from urllib.parse import urlparse

def http_hello_page(request, response):
    """
    Handles an HTTP request, extracts the username, and constructs a personalized greeting.

    Args:
        request: A file stream containing the HTTP request from the client.
        response: A file stream to write the HTTP response to.
    """

    # 1. Parse the request using cgi.FieldStorage for security.  This handles various content types.
    form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST' if request.method == 'POST' else 'GET'}, keep_blank_values=True)

    # 2. Validate the request method.  Only allow POST or GET.  If other methods are used, reject the request.
    if request.method not in ('POST', 'GET'):
        response.write(b"HTTP/1.1 405 Method Not Allowed\r\n")
        response.write(b"Content-Type: text/plain\r\n")
        response.write(b"\r\n")
        response.write(b"Method Not Allowed\r\n")
        return

    # 3. Extract the username, applying a strict allowlist.
    username = form.getvalue("username", "")  # Get the username, default to empty string

    # Strict allowlist: Only allow alphanumeric characters and spaces.
    if not isinstance(username, str):
        username = "" # Ensure username is a string
    
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    safe_username = "".join(c for c in username if c in allowed_chars)

    # 4. Sanitize the username to prevent XSS.  Escape HTML entities.
    escaped_username = html.escape(safe_username)

    # 5. Construct the response.
    greeting = f"Hello {escaped_username}!"
    response_body = greeting.encode("utf-8")

    # 6. Set HTTP headers, including content type and encoding.
    response.write(b"HTTP/1.1 200 OK\r\n")
    response.write(b"Content-Type: text/html; charset=utf-8\r\n")  # Specify encoding
    response.write(f"Content-Length: {len(response_body)}\r\n".encode("utf-8"))

    # 7. Set HttpOnly cookie (example - adapt to your session management).  This is crucial for session security.
    session_id = secrets.token_hex(16)  # Generate a random session ID
    cookie = http.cookies.SimpleCookie()
    cookie["sessionid"] = session_id
    cookie["sessionid"]["httponly"] = True  # Set HttpOnly flag
    response.write(f"{cookie.output()}\r\n".encode("utf-8"))

    response.write(b"\r\n")  # End of headers
    response.write(response_body)

    # 8.  Nonce and Double-Submitted Cookie (Example - adapt to your form).  This is a simplified example.  A real implementation would involve storing the nonce server-side and validating it on form submission.
    nonce = secrets.token_hex(16)
    double_submit_cookie = secrets.token_hex(16)

    # In a real application, you would:
    #   - Store the nonce server-side, associated with the user's session.
    #   - Include the nonce as a hidden field in the form.
    #   - Set the double-submit cookie.
    #   - On form submission, validate that the nonce in the request matches the stored nonce, and that the double-submit cookie is present and valid.

    # Example of how you might include the nonce in a form (this is just an example, not executable here):
    # <input type="hidden" name="nonce" value="{nonce}">
    # And set the double-submit cookie in the response.

    # 9. Validate the destination of any redirects or links (if applicable).  This example doesn't have redirects, but it's important to validate URLs.
    # Example:
    # def is_safe_url(url, allowed_hosts):
    #     try:
    #         result = urlparse(url)
    #         return result.scheme in ("http", "https") and result.netloc in allowed_hosts
    #     except:
    #         return False

    # allowed_hosts = ["example.com", "www.example.com"]  # Your allowed hosts
    # if redirect_url and is_safe_url(redirect_url, allowed_hosts):
    #     # Redirect
    #     pass
    # else:
    #     # Handle unsafe URL
    #     pass

    # 10.  Input Validation:  The allowlist on the username is a form of input validation.  More complex validation might be needed depending on the expected input.

    # 11.  Error Handling:  In a production environment, you would want to add more robust error handling (e.g., try-except blocks) to catch exceptions and return appropriate error responses.

    # 12.  Logging:  Log requests and responses for auditing and debugging purposes.  Be careful not to log sensitive information.
    # Example:
    # import logging
    # logging.info(f"Request: {request.method} {request.path}, Username: {safe_username}")
    # logging.info(f"Response: {greeting}")

    return

