import cgi
import html
import logging

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def http_hello_page(request, response):
    """
    Handles an HTTP request to greet a user by name.

    Args:
        request: A file-like object representing the HTTP request from the client.
        response: A file-like object to write the HTTP response to.
    """

    try:
        # Parse the request using cgi.FieldStorage.  This handles both GET and POST requests.
        form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST'})  # Assuming POST for security
        logging.debug(f"Form data: {form}")

        # Get the username from the form data.  Use a default value if not provided.
        username = form.getvalue("username", "Guest")  # Default to "Guest" if no username is provided

        # Sanitize the username to prevent XSS attacks.  Important!
        username = html.escape(username)

        # Construct the greeting message.
        greeting = f"Hello {username}"

        # Construct the HTTP response.  Include necessary headers.
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

        # Write the response to the response stream.
        response.write(response_text.encode('utf-8'))  # Encode to bytes

        logging.info(f"Successfully greeted user: {username}")

    except Exception as e:
        logging.exception("An error occurred while processing the request:")
        error_message = f"An error occurred: {str(e)}"
        error_response = f"""HTTP/1.1 500 Internal Server Error\r
Content-Type: text/html\r
\r
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
</head>
<body>
    <h1>Error</h1>
    <p>{error_message}</p>
</body>
</html>
"""
        response.write(error_response.encode('utf-8'))


if __name__ == '__main__':
    # Example usage (for testing purposes)
    # This simulates a request and response using StringIO.
    import io

    # Simulate a POST request with a username
    request_data = b"username=John+Doe"  # URL-encoded data
    request_stream = io.BytesIO(request_data)

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
    http_hello_page(request_stream, response_stream)
    response_content = response_stream.getvalue().decode('utf-8')
    print(response_content)

    # Simulate a POST request with a malicious username
    request_data = b"username=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"  # URL-encoded <script>alert('XSS')</script>
    request_stream = io.BytesIO(request_data)
    response_stream = io.BytesIO()
    http_hello_page(request_stream, response_stream)
    response_content = response_stream.getvalue().decode('utf-8')
    print(response_content)

