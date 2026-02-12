import html
import logging
import re
from urllib.parse import parse_qs

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MAX_USERNAME_LENGTH = 32  # Define a maximum username length

def http_hello_page(request, response):
    """
    Handles an HTTP request to greet a user by their username.

    Args:
        request: A file-like object representing the HTTP request from the client.
        response: A file-like object to write the HTTP response to.
    """

    try:
        # 1. Use urllib.parse for parsing request data
        request_body = request.read().decode('utf-8')
        form_data = parse_qs(request_body)
        username = form_data.get("username", ["Guest"])[0]  # Get first value, default to "Guest"

        # 2. Comprehensive Input Validation
        if not re.match(r"^[a-zA-Z0-9_.-]+$", username) or len(username) > MAX_USERNAME_LENGTH:
            username = "Invalid Username"
            logging.warning("Invalid username provided.")
        else:
            # 3. Contextual Output Encoding (HTML Escaping)
            username = html.escape(username)

        # Construct the response.
        greeting = f"Hello {username}"

        # Construct the HTTP response.  Include necessary headers.
        response_text = f"""\
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

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

        # Log the request (optional).
        logging.info(f"Served greeting to user: {username}")

    except Exception as e:
        # 4. Error Handling (Generic Error Message)
        error_message = "An unexpected error occurred. Please try again later."
        logging.exception("Error processing request", exc_info=True)  # Log the full exception

        error_response = f"""\
HTTP/1.1 500 Internal Server Error
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
</head>
<body>
    <h1>Internal Server Error</h1>
    <p>{error_message}</p>
</body>
</html>
"""
        response.write(error_response.encode('utf-8'))


if __name__ == '__main__':
    # Example usage (for testing purposes)
    # This is a simplified example and would need to be integrated into a proper web server.

    import io  # Import the io module for BytesIO

    # Simulate a request with a username.
    request_data = b"username=TestUser"  # Example POST data
    request_stream = io.BytesIO(request_data)

    # Create a response stream.
    response_stream = io.BytesIO()

    # Call the function.
    http_hello_page(request_stream, response_stream)

    # Print the response (for demonstration).
    response_content = response_stream.getvalue().decode('utf-8')
    print(response_content)

