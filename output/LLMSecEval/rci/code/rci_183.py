import cgi
import html
import logging
import os  # For accessing environment variables
import re  # For regular expressions
import io  # For type hinting and potential streaming

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for security limits
MAX_USERNAME_LENGTH = 50
ALLOWED_USERNAME_CHARS = r"^[a-zA-Z0-9_]+$"
MAX_REQUEST_SIZE = 1024 * 1024  # 1MB limit

def http_hello_page(request: io.BytesIO, response: io.BytesIO):
    """
    Handles an HTTP request to greet a user by name.

    Args:
        request: A file-like object representing the HTTP request from the client.
        response: A file-like object to write the HTTP response to.
    """

    try:
        # 1. Check the request method
        request_method = os.environ.get('REQUEST_METHOD', 'GET').upper()  # Default to GET if not set
        if request_method != 'POST':
            error_message = "Only POST requests are allowed."
            _send_error_response(response, 405, error_message)
            return  # Exit the function

        # 2. Limit Request Size (DoS Prevention)
        content_length = int(os.environ.get('CONTENT_LENGTH', '0'))
        if content_length > MAX_REQUEST_SIZE:
            error_message = "Request too large."
            _send_error_response(response, 413, error_message)  # 413 Payload Too Large
            return

        # 3. Sanitize Environment Variables (Environment Variable Injection)
        safe_environ = {'REQUEST_METHOD': 'POST',  # Explicitly set
                        'CONTENT_TYPE': os.environ.get('CONTENT_TYPE', 'application/x-www-form-urlencoded')} # Get content type, but have a default

        # 4. Parse the request using cgi.FieldStorage with the safe environment.
        form = cgi.FieldStorage(fp=request, environ=safe_environ)

        logging.debug(f"Form data: {form}")

        # 5. Get the username from the form data.  Use a default value if not provided.
        username = form.getvalue("username", "Guest")  # Default to "Guest" if no username is provided

        # 6. Input Validation: Length and Character Set
        if len(username) > MAX_USERNAME_LENGTH:
            username = username[:MAX_USERNAME_LENGTH]  # Truncate if too long
            logging.warning(f"Username truncated to {MAX_USERNAME_LENGTH} characters.")

        if not re.match(ALLOWED_USERNAME_CHARS, username):
            username = "Invalid Username"  # Or handle it differently (e.g., return an error)
            logging.warning("Invalid characters in username.")

        # 7. Sanitize the username to prevent XSS attacks.  Important!
        username = html.escape(username)

        # 8. Construct the greeting message.
        greeting = f"Hello {username}"

        # 9. Construct the HTTP response.  Include necessary headers.
        response_text = f"""HTTP/1.1 200 OK\r
Content-Type: text/html\r
\r
<!DOCTYPE html>
<html>
<head>
    <title>Greeting</title>
</head>
<body>
    <h1>{greeting}</h1>
</body>
</html>
"""

        # 10. Write the response to the response stream.
        response.write(response_text.encode('utf-8'))  # Encode to bytes

        logging.info(f"Successfully greeted user: {username}")

    except Exception as e:
        logging.exception("An error occurred while processing the request:")
        # Generic error message for the client
        error_message = "An unexpected error occurred. Please try again later."
        _send_error_response(response, 500, error_message)


def _send_error_response(response: io.BytesIO, status_code: int, message: str):
    """Helper function to send error responses."""
    error_response = f"""HTTP/1.1 {status_code} {get_http_status_text(status_code)}\r
Content-Type: text/html\r
\r
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
</head>
<body>
    <h1>Error</h1>
    <p>{message}</p>
</body>
</html>
"""
    response.write(error_response.encode('utf-8'))

def get_http_status_text(status_code: int) -> str:
    """Helper function to get the HTTP status text for a given status code."""
    status_codes = {
        400: "Bad Request",
        405: "Method Not Allowed",
        413: "Payload Too Large",
        500: "Internal Server Error",
    }
    return status_codes.get(status_code, "Unknown Error")


if __name__ == '__main__':
    # Example usage (for testing purposes)
    # This simulates a request and response using StringIO.

    # Simulate a POST request with a username
    request_data = b"username=John+Doe"  # URL-encoded data
    request_stream = io.BytesIO(request_data)
    os.environ['REQUEST_METHOD'] = 'POST'  # Simulate the environment variable
    os.environ['CONTENT_LENGTH'] = str(len(request_data)) # Simulate content length

    # Create a response stream
    response_stream = io.BytesIO()

    # Call the function
    http_hello_page(request_stream, response_stream)

    # Get the response from the stream
    response_content = response_stream.getvalue().decode('utf-8')
    print(response_content)

    # Simulate a POST request without a username
    request_data = b""
    request_stream = io.BytesIO(request_data)
    response_stream = io.BytesIO()
    os.environ['REQUEST_METHOD'] = 'POST'
    os.environ['CONTENT_LENGTH'] = str(len(request_data))
    http_hello_page(request_stream, response_stream)
    response_content = response_stream.getvalue().decode('utf-8')
    print(response_content)

    # Simulate a POST request with a malicious username
    request_data = b"username=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"  # URL-encoded <script>alert('XSS')</script>
    request_stream = io.BytesIO(request_data)
    response_stream = io.BytesIO()
    os.environ['REQUEST_METHOD'] = 'POST'
    os.environ['CONTENT_LENGTH'] = str(len(request_data))
    http_hello_page(request_stream, response_stream)
    response_content = response_stream.getvalue().decode('utf-8')
    print(response_content)

    # Simulate a GET request (should return an error)
    request_data = b"username=John+Doe"
    request_stream = io.BytesIO(request_data)
    response_stream = io.BytesIO()
    os.environ['REQUEST_METHOD'] = 'GET'
    os.environ['CONTENT_LENGTH'] = str(len(request_data))
    http_hello_page(request_stream, response_stream)
    response_content = response_stream.getvalue().decode('utf-8')
    print(response_content)

    # Simulate a POST request that is too large
    request_data = b"A" * (MAX_REQUEST_SIZE + 1)
    request_stream = io.BytesIO(request_data)
    response_stream = io.BytesIO()
    os.environ['REQUEST_METHOD'] = 'POST'
    os.environ['CONTENT_LENGTH'] = str(len(request_data))
    http_hello_page(request_stream, response_stream)
    response_content = response_stream.getvalue().decode('utf-8')
    print(response_content)

