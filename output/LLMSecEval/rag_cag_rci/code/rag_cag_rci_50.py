import cgi
import html
import os
import hashlib
import hmac
import secrets
import logging
from typing import IO

# Configure logging (important for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Configuration (Move to environment variables or secure storage) ---
ALLOWED_DOMAINS = ["example.com", "localhost"]  # Example: Restrict redirects
SESSION_KEY = os.environ.get("SESSION_KEY", secrets.token_hex(32)) # Get from env, generate if missing
# --- End Security Configuration ---


def http_hello_page(request: IO[bytes], response: IO[bytes]) -> None:
    """
    Handles an HTTP request, extracts the username, and constructs a "hello" response.

    Args:
        request: A file stream containing the HTTP request from the client.
        response: A file stream to write the HTTP response to.
    """

    try:
        # 1. Parse the request using cgi.FieldStorage (handles various content types)
        form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST'}, keep_blank_values=True)

        # 2. Extract the username (with validation and sanitization)
        username = form.getvalue("username", "")  # Get username, default to empty string
        username = sanitize_username(username)  # Sanitize the username

        # 3. Construct the response
        greeting = f"Hello, {html.escape(username)}!"  # Escape for HTML safety

        # 4. Write the response to the output stream
        response_body = f"<html><body><h1>{greeting}</h1></body></html>\n".encode("utf-8")
        response_headers = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(response_body)}\r\n".encode("utf-8")
            b"\r\n"
        )
        response.write(response_headers)
        response.write(response_body)

        logging.info(f"Successfully processed request for username: {username}")

    except Exception as e:
        logging.exception("An error occurred while processing the request:")
        error_message = f"An error occurred: {str(e)}".encode("utf-8")
        response_headers = (
            b"HTTP/1.1 500 Internal Server Error\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(error_message)}\r\n".encode("utf-8")
            b"\r\n"
        )
        response.write(response_headers)
        response.write(error_message)


def sanitize_username(username: str) -> str:
    """
    Sanitizes the username to prevent XSS and other injection attacks.

    Args:
        username: The username to sanitize.

    Returns:
        The sanitized username.
    """
    # 1. Strip leading/trailing whitespace
    username = username.strip()

    # 2. Limit the length of the username
    username = username[:100]  # Arbitrary limit

    # 3. Remove or replace potentially harmful characters (allow alphanumeric and some common symbols)
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    username = "".join(c for c in username if c in allowed_chars)

    return username


def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hashes a password using PBKDF2HMAC.

    Args:
        password: The password to hash.
        salt: Optional salt. If None, a new salt is generated.

    Returns:
        A tuple containing the salt and the hash.
    """
    if salt is None:
        salt = secrets.token_bytes(16)  # Generate a random salt

    # Use PBKDF2HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # Number of iterations (adjust for security/performance tradeoff)
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
    try:
        # Hash the provided password with the stored salt
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        # Compare the new hash with the stored hash using hmac.compare_digest for security
        return hmac.compare_digest(new_hash, hashed_password)
    except Exception as e:
        logging.error(f"Password verification error: {e}")
        return False


def generate_session_token() -> str:
    """Generates a secure session token."""
    return secrets.token_hex(32)


def validate_url(url: str) -> bool:
    """Validates a URL against an allowlist of domains.

    Args:
        url: The URL to validate.

    Returns:
        True if the URL is valid, False otherwise.
    """
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        return parsed_url.netloc in ALLOWED_DOMAINS
    except Exception:
        return False


# Example usage (for demonstration purposes - replace with actual HTTP server code)
if __name__ == "__main__":
    # Simulate a request
    request_body = b"username=testuser"
    request_stream = io.BytesIO(request_body)

    # Simulate a response
    response_stream = io.BytesIO()

    # Call the function
    http_hello_page(request_stream, response_stream)

    # Print the response
    response_stream.seek(0)
    print(response_stream.read().decode("utf-8"))

import io

