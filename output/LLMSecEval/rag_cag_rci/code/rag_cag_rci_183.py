import cgi
import html
import os
import hashlib
import hmac
import secrets
from typing import IO
from urllib.parse import urlparse

# --- Security Configuration (Move to environment variables or secure storage) ---
ALLOWED_DOMAINS = ["example.com", "localhost"]  # Example, configure properly
SESSION_KEY = os.environ.get("SESSION_KEY", secrets.token_hex(32)) # Get from env, generate if missing
# --- End Security Configuration ---


def http_hello_page(request: IO[bytes], response: IO[bytes]) -> None:
    """
    Handles an HTTP request, extracts the username, and constructs a personalized
    "Hello [username]" response.  Implements security best practices.

    Args:
        request: A file-like object representing the incoming HTTP request.
        response: A file-like object to write the HTTP response to.
    """

    try:
        # 1. Parse the request using cgi.FieldStorage (handles various encodings)
        form = cgi.FieldStorage(fp=request.makefile('r', encoding='utf-8'),
                                environ={'REQUEST_METHOD': 'POST'},
                                keep_blank_values=True)

        # 2. Extract the username, with robust validation and sanitization
        username = form.getvalue("username")
        if not username:
            username = "Guest"  # Default if no username provided

        # 3. Sanitize the username to prevent XSS attacks
        username = html.escape(username)  # Escape HTML entities

        # 4. Construct the response
        response_text = f"Hello {username}!\n"

        # 5. Write the response to the output stream
        response_header = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(response_text.encode('utf-8'))}\r\n"
            "\r\n"
        )
        response.write(response_header.encode('utf-8'))
        response.write(response_text.encode('utf-8'))

    except Exception as e:
        # 6. Handle errors gracefully (log the error, return a generic error page)
        print(f"Error processing request: {e}")  # Log the error (use a proper logger)
        error_message = "Internal Server Error"
        response_header = (
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(error_message.encode('utf-8'))}\r\n"
            "\r\n"
        )
        response.write(response_header.encode('utf-8'))
        response.write(error_message.encode('utf-8'))


# --- Example Authentication Functions (Illustrative) ---

def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hashes a password using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_bytes(16)  # Generate a random salt
    password_bytes = password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        iterations=100000  # Adjust iterations for security
    )
    return hashed_password, salt


def verify_password(password: str, stored_hash: bytes, salt: bytes) -> bool:
    """Verifies a password against a stored hash and salt."""
    hashed_password, _ = hash_password(password, salt)  # Hash with the stored salt
    return hmac.compare_digest(hashed_password, stored_hash)  # Constant-time comparison


def is_valid_url(url: str) -> bool:
    """Validates a URL against an allowlist of domains."""
    try:
        result = urlparse(url)
        if result.netloc in ALLOWED_DOMAINS:
            return True
        else:
            return False
    except:
        return False

def sanitize_file_path(file_path: str) -> str:
    """Sanitizes a file path to prevent path traversal attacks."""
    # Normalize the path
    file_path = os.path.normpath(file_path)

    # Check for ".." patterns
    if ".." in file_path:
        raise ValueError("Invalid file path: Path traversal detected.")

    return file_path

# --- Example Usage (Illustrative) ---
if __name__ == '__main__':
    # Simulate a request
    request_data = b"username=TestUser&other_field=value"  # Example POST data
    request_file = open("request.txt", "wb")
    request_file.write(request_data)
    request_file.close()
    request_file = open("request.txt", "rb")

    # Simulate a response
    response_file = open("response.txt", "wb")

    http_hello_page(request_file, response_file)

    request_file.close()
    response_file.close()

    # Read the response
    with open("response.txt", "r") as f:
        print("Response:", f.read())

    os.remove("request.txt")
    os.remove("response.txt")

