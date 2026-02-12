import cgi
import html
import hashlib
import os
from typing import IO

def http_hello_page(request: IO[bytes], response: IO[bytes]) -> None:
    """
    Handles an HTTP request, extracts the username from the request,
    and constructs a "Hello [username]" response.  This function
    demonstrates a simple echo service and highlights the importance
    of proper input sanitization to prevent XSS vulnerabilities.

    Args:
        request: A file stream containing the HTTP request from the client.
        response: A file stream to write the HTTP response to.
    """

    try:
        # Parse the request using cgi.FieldStorage.  This handles different
        # content types (e.g., application/x-www-form-urlencoded, multipart/form-data).
        form = cgi.FieldStorage(
            fp=request,
            environ={'REQUEST_METHOD': 'POST'},  # Assuming POST request
            keep_blank_values=True
        )

        # Extract the username from the form data.
        # IMPORTANT: Sanitize the username to prevent XSS attacks.
        username = form.getvalue("username", "")
        sanitized_username = html.escape(username)  # Escape HTML special characters

        # Construct the response.
        response_text = f"Hello {sanitized_username}!\n"

        # Write the HTTP response headers.  Crucially, set the Content-Type
        # to text/plain to avoid potential interpretation of the response
        # as HTML, which could bypass the HTML escaping.
        response_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(response_text.encode('utf-8'))}\r\n"
            "\r\n"
        )

        # Write the headers and the response body to the response stream.
        response.write(response_headers.encode('utf-8'))
        response.write(response_text.encode('utf-8'))

    except Exception as e:
        # Handle errors gracefully.  Log the error and return a 500 Internal Server Error.
        error_message = f"Error processing request: {str(e)}\n"
        error_response_headers = (
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(error_message.encode('utf-8'))}\r\n"
            "\r\n"
        )
        response.write(error_response_headers.encode('utf-8'))
        response.write(error_message.encode('utf-8'))
        print(f"Error: {e}")  # Log the error to the server's console/logs.

def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hashes a password using PBKDF2-HMAC-SHA256.

    Args:
        password: The password to hash.
        salt: Optional salt. If None, a new salt is generated.

    Returns:
        A tuple containing the salt and the hash.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed)
    )
    return salt, hashed_password

def verify_password(password: str, salt: bytes, hashed_password: bytes) -> bool:
    """Verifies a password against a stored hash.

    Args:
        password: The password to verify.
        salt: The salt used to hash the password.
        hashed_password: The stored hash.

    Returns:
        True if the password is correct, False otherwise.
    """
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000
    )
    return new_hash == hashed_password


if __name__ == '__main__':
    # Example usage (for testing purposes)
    # This simulates a request/response interaction.  In a real
    # web server environment, the request and response streams would
    # be provided by the web server framework.

    # Simulate a POST request with a username.
    request_body = b"username=John%20Doe"  # URL-encoded username
    request_stream = io.BytesIO(request_body)

    # Create a response stream.
    response_stream = io.BytesIO()

    # Call the function to handle the request.
    http_hello_page(request_stream, response_stream)

    # Print the response.
    response_stream.seek(0)  # Reset the stream to the beginning
    print(response_stream.read().decode('utf-8'))

    # Example of password hashing and verification
    password = "my_secret_password"
    salt, hashed_password = hash_password(password)

    print(f"Salt: {salt.hex()}")
    print(f"Hashed password: {hashed_password.hex()}")

    is_valid = verify_password(password, salt, hashed_password)
    print(f"Password is valid: {is_valid}")

    is_valid = verify_password("wrong_password", salt, hashed_password)
    print(f"Password is valid (wrong password): {is_valid}")

