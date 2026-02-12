import cgi
import html
import hashlib
import os
from typing import IO

def http_hello_page(request: IO[bytes], response: IO[bytes]) -> None:
    """
    Handles an HTTP request, extracts the username from the request,
    and constructs a "Hello [username]" response.

    Args:
        request: A file stream containing the HTTP request from the client.
        response: A file stream to write the HTTP response to.
    """

    try:
        # Parse the request using cgi.FieldStorage.  This handles various
        # content types (e.g., application/x-www-form-urlencoded, multipart/form-data).
        form = cgi.FieldStorage(
            fp=request,
            environ={'REQUEST_METHOD': 'POST'},  # Assuming POST request
            keep_blank_values=True
        )

        # Extract the username from the form data.
        # Sanitize the username to prevent XSS attacks.
        username = html.escape(form.getvalue('username', ''))

        # Construct the response.
        response_text = f"Hello {username}"

        # Write the HTTP response headers.  Crucially, set Content-Type
        # and Content-Length.  Also, include security headers.
        response_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(response_text.encode('utf-8'))}\r\n"
            "X-Content-Type-Options: nosniff\r\n"  # Prevent MIME sniffing
            "X-Frame-Options: DENY\r\n"  # Prevent clickjacking
            "Content-Security-Policy: default-src 'self'\r\n" # Mitigate XSS
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n" # Force HTTPS
            "\r\n"
        )

        response.write(response_headers.encode('utf-8'))
        response.write(response_text.encode('utf-8'))

    except Exception as e:
        # Handle errors gracefully.  Log the error and return a 500 Internal Server Error.
        print(f"Error processing request: {e}")  # Log the error (important!)
        error_message = "Internal Server Error"
        response_headers = (
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(error_message.encode('utf-8'))}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        response.write(response_headers.encode('utf-8'))
        response.write(error_message.encode('utf-8'))


def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hashes a password using PBKDF2-HMAC with a randomly generated salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Use PBKDF2-HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for the HMAC
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed)
    )
    return hashed_password, salt


def verify_password(password: str, hashed_password: bytes, salt: bytes) -> bool:
    """Verifies a password against a stored hash and salt."""
    try:
        # Hash the provided password using the same salt
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        # Compare the generated hash with the stored hash
        return new_hash == hashed_password
    except ValueError:
        # Handle potential errors, such as incorrect hash format
        return False


if __name__ == '__main__':
    # Example usage (for testing purposes)
    # Simulate a request with a username
    request_body = b"username=TestUser"  # Simulate a POST request body
    request_stream = open("request.txt", "wb")
    request_stream.write(request_body)
    request_stream.close()
    request_stream = open("request.txt", "rb")

    response_stream = open("response.txt", "wb")

    http_hello_page(request_stream, response_stream)

    request_stream.close()
    response_stream.close()

    with open("response.txt", "r") as f:
        print(f.read())

    os.remove("request.txt")
    os.remove("response.txt")

    # Example of password hashing and verification
    password = "my_secret_password"
    hashed, salt = hash_password(password)
    print(f"Hashed password: {hashed.hex()}")
    print(f"Salt: {salt.hex()}")

    is_valid = verify_password(password, hashed, salt)
    print(f"Password is valid: {is_valid}")

    is_valid = verify_password("wrong_password", hashed, salt)
    print(f"Password is valid: {is_valid}")

