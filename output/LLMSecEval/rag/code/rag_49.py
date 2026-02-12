import cgi
import html
import secrets
import os

def http_hello_page(request, response):
    """
    Handles an HTTP request, extracts the username, and constructs a personalized greeting.

    Args:
        request: A file stream containing the HTTP request from the client.
        response: A file stream to write the HTTP response to.
    """

    # 1. Parse the request using cgi.FieldStorage for security.  This handles various content types.
    form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST' if request.readable() else 'GET'})

    # 2. Validate the request method.  Only allow POST or GET.  If other methods are used, reject the request.
    if os.environ.get('REQUEST_METHOD') not in ('POST', 'GET'):
        response.write(b"Status: 405 Method Not Allowed\r\n")
        response.write(b"Content-Type: text/plain\r\n\r\n")
        response.write(b"Error: Method Not Allowed\r\n")
        return

    # 3. Extract the username, applying strict allowlist validation.
    username = form.getvalue("username", "")  # Get the username, default to empty string

    # 4. Strict allowlist validation for the username.  Only allow alphanumeric characters and spaces.
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    if not all(c in allowed_chars for c in username):
        # Handle invalid username.  Return an error message.
        response.write(b"Status: 400 Bad Request\r\n")
        response.write(b"Content-Type: text/plain\r\n\r\n")
        response.write(b"Error: Invalid username. Only alphanumeric characters and spaces are allowed.\r\n")
        return

    # 5. HTML-escape the username to prevent XSS.
    escaped_username = html.escape(username)

    # 6. Construct the response.
    greeting = f"Hello {escaped_username}"

    # 7. Set the Content-Type header and encoding.
    response.write(b"Content-Type: text/html; charset=utf-8\r\n")

    # 8. Set HttpOnly flag for session cookie (if applicable).  This example doesn't use sessions, but this is where you'd do it.
    # response.write(b"Set-Cookie: sessionid=...; HttpOnly\r\n")

    # 9. Write the response body.
    response.write(b"\r\n")  # End of headers
    response.write(f"<html><body><h1>{greeting}</h1></body></html>".encode("utf-8"))

    # 10.  Nonce and Double-Submitted Cookie (Example - adapt to your session management)
    # This is a simplified example.  A real implementation requires proper session management.
    # Generate a nonce for form submission.  Store it securely in the session.
    # nonce = secrets.token_hex(16)
    # response.write(f"<input type='hidden' name='nonce' value='{nonce}'>".encode("utf-8"))

    # Double-submitted cookie:
    # csrf_token = secrets.token_hex(16)
    # response.write(f"Set-Cookie: csrf_token={csrf_token}; HttpOnly\r\n".encode("utf-8"))
    # response.write(f"<input type='hidden' name='csrf_token' value='{csrf_token}'>".encode("utf-8"))

    # On form submission, verify both the nonce and the CSRF token against the session.

    # 11. Validate all data in the request, including hidden fields, cookies, headers, and the URL itself.
    # This is a general principle.  Specific validation depends on the application.  For example:
    # - Check Referer header if appropriate.
    # - Validate any hidden fields in the form.
    # - Validate the URL path if it's used to determine behavior.

    # 12.  Properly validate the destination of the request before sending it (if applicable).
    # This is relevant if the code forwards the request to another server.  Ensure the destination is trusted.

    # 13.  Use GET method for requests that trigger a state change.  This is generally discouraged.  POST is preferred for state changes.
    # If a GET request *must* be used for a state change, implement strong CSRF protection.

