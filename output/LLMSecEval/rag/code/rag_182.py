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

    # 1. Parse the request using cgi.FieldStorage for robust handling of various request types (GET/POST).
    form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST' if request.readable() else 'GET'})

    # 2. Validate the request method (e.g., only allow POST for username submission).  This example assumes POST.
    if os.environ.get('REQUEST_METHOD') != 'POST':
        error_message = "Error: Only POST requests are allowed for username submission."
        response.write(f"HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><h1>{error_message}</h1></body></html>".encode('utf-8'))
        return

    # 3. Extract the username from the request, applying strict validation.
    username = form.getvalue("username")

    if not username:
        error_message = "Error: Username is missing."
        response.write(f"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><h1>{error_message}</h1></body></html>".encode('utf-8'))
        return

    # 4. Strict allowlist validation of the username.  Only allow alphanumeric characters and spaces.
    if not all(c.isalnum() or c.isspace() for c in username):
        error_message = "Error: Invalid username. Only alphanumeric characters and spaces are allowed."
        response.write(f"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><h1>{error_message}</h1></body></html>".encode('utf-8'))
        return

    # 5. Sanitize the username to prevent XSS attacks.  Escape HTML entities.
    escaped_username = html.escape(username)

    # 6. Construct the personalized greeting.
    greeting = f"Hello {escaped_username}!"

    # 7. Generate a unique nonce for form submissions (example, not directly used here but important for other forms).
    nonce = secrets.token_urlsafe(16)  # Generate a cryptographically secure random string

    # 8. Set the session cookie to HttpOnly (example, assuming you have a session management mechanism).
    #   This requires a session management system (e.g., using a library like `itsdangerous` or `Flask-Session`).
    #   For simplicity, we'll just show how to set the header.  In a real application, you'd integrate this with your session management.
    #   Example:  response.write(f"Set-Cookie: sessionid={session_id}; HttpOnly\r\n".encode('utf-8'))

    # 9. Construct the HTML response, including Content-Type and character encoding.
    html_response = f"""HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n
    <!DOCTYPE html>
    <html>
    <head>
        <title>Hello Page</title>
    </head>
    <body>
        <h1>{greeting}</h1>
        <!-- Example of a form with a hidden nonce field (for other forms) -->
        <form method="POST" action="/some_other_page">
            <input type="hidden" name="nonce" value="{nonce}">
            <!-- Other form fields -->
            <button type="submit">Submit</button>
        </form>
    </body>
    </html>
    """

    # 10. Write the response to the response stream, encoding it as UTF-8.
    response.write(html_response.encode('utf-8'))


# Example usage (for testing):
if __name__ == '__main__':
    # Simulate a request with a username.
    # In a real web server, the request would be a socket stream.
    request_data = b"username=John+Doe"  # Example POST data
    request_stream = open("request.txt", "wb")
    request_stream.write(request_data)
    request_stream.close()
    request_stream = open("request.txt", "rb")
    os.environ['REQUEST_METHOD'] = 'POST' # Set the request method for cgi.FieldStorage

    # Create a response stream (e.g., a file or socket).
    response_stream = open("response.txt", "wb")

    # Call the function.
    http_hello_page(request_stream, response_stream)

    # Close the streams.
    request_stream.close()
    response_stream.close()

    # Print the response (for testing).
    with open("response.txt", "r", encoding="utf-8") as f:
        print(f.read())

    os.remove("request.txt")
    os.remove("response.txt")

