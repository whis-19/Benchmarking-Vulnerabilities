import cgi
import html
import logging
import secrets  # For CSRF token generation
import os

# Configure logging (e.g., to a file)
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# In a real application, store CSRF tokens securely in a session.
# This is a simplified example for demonstration purposes only.
csrf_tokens = {}


def generate_csrf_token(user_id):
    """Generates a CSRF token for a user."""
    token = secrets.token_urlsafe(16)  # Generate a random token
    csrf_tokens[user_id] = token
    return token


def verify_csrf_token(user_id, token):
    """Verifies a CSRF token."""
    if user_id in csrf_tokens and csrf_tokens[user_id] == token:
        del csrf_tokens[user_id]  # Consume the token after use
        return True
    return False


def http_hello_page(request, response, user_id=123):  # Added user_id for CSRF example
    """
    Handles an HTTP request to greet a user by their username.

    Args:
        request: A file stream containing the HTTP request from the client.
        response: A file stream to write the HTTP response to.
        user_id:  A unique identifier for the user (for CSRF).
    """

    try:
        # 1. Check request method
        request_method = request.environ.get('REQUEST_METHOD', 'GET')
        if request_method != 'POST':
            response_content = "This endpoint only accepts POST requests."
            response.write(f"Content-Type: text/html; charset=utf-8\r\n\r\n{response_content}")
            return

        # 2. Check request body size (DoS protection)
        content_length = int(request.environ.get('CONTENT_LENGTH', 0))
        max_content_length = 1024  # Example: 1KB limit
        if content_length > max_content_length:
            logging.warning(f"Request body exceeds maximum allowed size ({max_content_length} bytes)")
            response_content = f"Request body too large. Maximum size is {max_content_length} bytes."
            response.write(f"Content-Type: text/html; charset=utf-8\r\n\r\n{response_content}")
            return


        # 3. Parse the request using cgi.FieldStorage for security.
        form = cgi.FieldStorage(fp=request, environ=request.environ)

        # 4. CSRF protection
        csrf_token = form.getvalue("csrf_token", "")
        if not verify_csrf_token(user_id, csrf_token):
            logging.warning(f"CSRF token verification failed for user {user_id}")
            response_content = "CSRF token is invalid."
            response.write(f"Content-Type: text/html; charset=utf-8\r\n\r\n{response_content}")
            return

        # 5. Extract the username from the request.  Use a stringent allowlist.
        username = form.getvalue("username", "")

        if username:
            if not all(c.isalnum() or c.isspace() for c in username):
                # Handle invalid username.  Return an error message.
                logging.warning(f"Invalid username attempt: {username[:50]}...")  # Log only the first 50 chars
                response_content = "Invalid username. Only alphanumeric characters and spaces are allowed."
                response.write(f"Content-Type: text/html; charset=utf-8\r\n\r\n{response_content}")
                return

            # HTML encode the username to prevent XSS attacks.
            escaped_username = html.escape(username)
            response_content = f"Hello {escaped_username}"
        else:
            response_content = "Please enter a username."

        # 6. Set the Content-Type header with charset.
        # 7. Write the response to the response stream.
        response.write(f"Content-Type: text/html; charset=utf-8\r\n\r\n{response_content}")

    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full exception
        response_content = "An error occurred while processing your request."
        response.write(f"Content-Type: text/html; charset=utf-8\r\n\r\n{response_content}")


# Example usage (for testing purposes):
if __name__ == '__main__':
    # Simulate a request with a username.
    # In a real web server environment, the request would come from the client.
    # This is just for local testing.
    class MockRequest:
        def __init__(self, username, method='POST', csrf_token="", content_length=None, content=None):
            self.username = username
            self.method = method
            self.csrf_token = csrf_token
            self.environ = {'REQUEST_METHOD': method}
            if content_length is not None:
                self.environ['CONTENT_LENGTH'] = str(content_length)
            self.content = content

        def read(self, size=None):
            # Simulate a POST request with form data.
            if self.content:
                return self.content.encode('utf-8')
            data = f"username={self.username}"
            if self.csrf_token:
                data += f"&csrf_token={self.csrf_token}"
            return data.encode('utf-8')

        def readline(self):
            return b""  # Not used in this simplified example

    class MockResponse:
        def __init__(self):
            self.content = ""

        def write(self, data):
            self.content += data

    user_id = 123
    csrf_token = generate_csrf_token(user_id)

    # Test case 1: Valid username with CSRF
    request = MockRequest("John Doe", csrf_token=csrf_token)
    response = MockResponse()
    http_hello_page(request, response, user_id)
    print(f"Test 1 Response: {response.content}")

    # Test case 2: Invalid username (contains special characters)
    request = MockRequest("John<script>alert('XSS')</script>Doe", csrf_token=csrf_token)
    response = MockResponse()
    http_hello_page(request, response, user_id)
    print(f"Test 2 Response: {response.content}")

    # Test case 3: Empty username
    request = MockRequest("", csrf_token=csrf_token)
    response = MockResponse()
    http_hello_page(request, response, user_id)
    print(f"Test 3 Response: {response.content}")

    # Test case 4: Invalid CSRF token
    request = MockRequest("John Doe", csrf_token="invalid_token")
    response = MockResponse()
    http_hello_page(request, response, user_id)
    print(f"Test 4 Response: {response.content}")

    # Test case 5: GET request
    request = MockRequest("John Doe", method="GET")
    response = MockResponse()
    http_hello_page(request, response, user_id)
    print(f"Test 5 Response: {response.content}")

    # Test case 6: Request body too large
    long_username = "A" * 2048  # Create a long username
    request = MockRequest(long_username, csrf_token=csrf_token, content_length=len(f"username={long_username}&csrf_token={csrf_token}"), content=f"username={long_username}&csrf_token={csrf_token}")
    response = MockResponse()
    http_hello_page(request, response, user_id)
    print(f"Test 6 Response: {response.content}")

