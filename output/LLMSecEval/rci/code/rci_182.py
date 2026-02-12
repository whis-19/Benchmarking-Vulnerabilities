import cgi
import html
import logging
import secrets
import re
import io  # Import io for BytesIO

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Dummy function for session retrieval (replace with your actual session management)
def get_session_csrf_token(request):
    """
    Retrieves the CSRF token from the user's session.  This is a placeholder.
    In a real application, you would use a session management library.
    """
    # Replace this with your actual session retrieval logic
    return "DUMMY_CSRF_TOKEN"  # REPLACE THIS!

def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(16)

def send_error_response(response, status_code, message):
    """Sends an error response to the client."""
    error_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Error</title>
    </head>
    <body>
        <h1>{message}</h1>
    </body>
    </html>
    """
    response.write(f"HTTP/1.1 {status_code}\r\n".encode("utf-8"))
    response.write("Content-Type: text/html\r\n".encode("utf-8"))
    response.write("X-Frame-Options: SAMEORIGIN\r\n".encode("utf-8"))
    response.write("X-Content-Type-Options: nosniff\r\n".encode("utf-8"))
    response.write("\r\n".encode("utf-8"))
    response.write(error_html.encode("utf-8"))

def http_hello_page(request, response):
    """
    Handles an HTTP request to greet a user by name.

    Args:
        request: A file-like object representing the HTTP request from the client.
        response: A file-like object to write the HTTP response to.
    """

    try:
        # Parse the request using cgi.FieldStorage.  This is safer than manually parsing.
        form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST'})  # Assuming POST request

        # CSRF Protection
        csrf_token = form.getfirst("csrf_token")
        session_csrf_token = get_session_csrf_token(request)  # Replace with your session retrieval

        if not csrf_token or csrf_token != session_csrf_token:
            logging.warning("CSRF token invalid.") # Log the event
            send_error_response(response, "400 Bad Request", "Error: CSRF token invalid.")
            return

        # Get the username from the form data.  Use getfirst() to handle multiple values safely.
        username = form.getfirst("username")

        if username:
            # Input Validation
            MAX_USERNAME_LENGTH = 50
            if len(username) > MAX_USERNAME_LENGTH:
                send_error_response(response, "400 Bad Request", "Error: Username too long.")
                return

            if not re.match(r"^[a-zA-Z0-9]+$", username): # Removed space from regex
                send_error_response(response, "400 Bad Request", "Error: Invalid characters in username.")
                return

            # Sanitize the username to prevent XSS vulnerabilities.  Crucial!
            safe_username = html.escape(username)

            # Construct the response.
            greeting = f"Hello {safe_username}"
            html_response = f"""
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

            # Write the HTTP response headers.  Important for proper communication.
            response.write("HTTP/1.1 200 OK\r\n".encode("utf-8"))
            response.write("Content-Type: text/html\r\n".encode("utf-8"))
            response.write("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n".encode("utf-8"))
            response.write("Content-Security-Policy: default-src 'self'\r\n".encode("utf-8")) # Refine this!
            response.write("X-Frame-Options: SAMEORIGIN\r\n".encode("utf-8"))
            response.write("X-Content-Type-Options: nosniff\r\n".encode("utf-8"))
            response.write("\r\n".encode("utf-8"))  # End of headers

            # Write the HTML response body.
            response.write(html_response.encode("utf-8"))  # Encode to bytes

        else:
            # Handle the case where the username is missing.  Return an error.
            send_error_response(response, "400 Bad Request", "Error: Username is required.")

    except Exception as e:
        # Handle any exceptions that occur during processing.  Log the error.
        logging.exception("An error occurred while processing the request:")
        send_error_response(response, "500 Internal Server Error", "An unexpected error occurred. Please try again later.")


# Example usage (for testing - replace with your actual server setup)
if __name__ == '__main__':
    # Simulate a request
    request_data = b"username=John+Doe&csrf_token=DUMMY_CSRF_TOKEN"  # Example POST data
    request_stream = io.BytesIO(request_data)

    # Simulate a response
    response_stream = io.BytesIO()

    # Call the function
    http_hello_page(request_stream, response_stream)

    # Print the response (for testing)
    response_stream.seek(0)  # Reset the stream to the beginning
    print(response_stream.read().decode("utf-8"))

