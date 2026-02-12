import cgi
import html
import hashlib
import os
import secrets
import time
from typing import IO, Tuple, Dict
from urllib.parse import urlparse

# Security: Rate limiting (in-memory, simple example)
login_attempts = {}  # type: Dict[str, Tuple[int, float]]
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

# Security: Allowed domains (example)
ALLOWED_DOMAINS = ["example.com", "localhost"]

# Security: Allowed file extensions (example)
ALLOWED_FILE_EXTENSIONS = [".txt", ".pdf", ".jpg", ".jpeg", ".png"]

# Security: Session management (very basic example)
session_store = {}  # type: Dict[str, Dict]
SESSION_TIMEOUT = 3600  # seconds

def is_domain_allowed(url: str) -> bool:
    """
    Checks if the domain of a URL is in the allowlist.
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname is None:
            return False  # or raise an exception, depending on your needs
        return hostname in ALLOWED_DOMAINS
    except Exception:
        return False  # Handle parsing errors safely

def validate_file_extension(filename: str) -> bool:
    """
    Validates that a file has an allowed extension.
    """
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_FILE_EXTENSIONS

def prevent_path_traversal(filepath: str) -> str:
    """
    Normalizes a file path to prevent path traversal attacks.
    """
    normalized_path = os.path.normpath(filepath)
    if ".." in normalized_path:
        raise ValueError("Path traversal detected!")
    return normalized_path

def hash_password(password: str) -> str:
    """
    Hashes a password using SHA-256.  **IMPORTANT:**  In a real application,
    use bcrypt, scrypt, or PBKDF2 instead.  This is for demonstration only.
    """
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return f"{salt}:{hashed_password}"

def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verifies a password against a stored hash.
    """
    try:
        salt, hash_value = hashed_password.split(":", 1)
        salted_password = salt + password
        new_hash = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
        return new_hash == hash_value
    except ValueError:
        return False  # Invalid hash format

def rate_limit(ip_address: str) -> bool:
    """
    Implements rate limiting for login attempts.  Returns True if rate limited, False otherwise.
    """
    now = time.time()
    if ip_address in login_attempts:
        attempts, last_attempt_time = login_attempts[ip_address]
        if now - last_attempt_time < LOCKOUT_DURATION and attempts >= MAX_LOGIN_ATTEMPTS:
            return True  # Rate limited
        elif now - last_attempt_time >= LOCKOUT_DURATION:
            # Reset attempts after lockout duration
            login_attempts[ip_address] = (1, now)
        else:
            login_attempts[ip_address] = (attempts + 1, now)
    else:
        login_attempts[ip_address] = (1, now)
    return False

def create_session(user_id: int) -> str:
    """
    Creates a new session and returns the session ID.
    """
    session_id = secrets.token_hex(16)
    session_store[session_id] = {"user_id": user_id, "last_activity": time.time()}
    return session_id

def get_user_id_from_session(session_id: str) -> int | None:
    """
    Retrieves the user ID from a session ID.  Returns None if the session is invalid or expired.
    """
    if session_id in session_store:
        session = session_store[session_id]
        if time.time() - session["last_activity"] < SESSION_TIMEOUT:
            session["last_activity"] = time.time()  # Update last activity
            return session["user_id"]
        else:
            del session_store[session_id]  # Session expired
            return None
    else:
        return None

def destroy_session(session_id: str) -> None:
    """
    Destroys a session.
    """
    if session_id in session_store:
        del session_store[session_id]

def http_hello_page(request: IO[bytes], response: IO[bytes]) -> None:
    """
    Handles an HTTP request, extracts the username, and sends a personalized greeting.
    """
    form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST'}, keep_blank_values=True)

    # Security: Input validation and sanitization
    if 'username' in form:
        username = form['username'].value
        if not isinstance(username, str):
            username = str(username) # Ensure it's a string

        # Stringent allowlist for username characters (alphanumeric and underscore)
        if not all(c.isalnum() or c == '_' for c in username):
            response_body = b"Invalid username.  Only alphanumeric characters and underscores are allowed."
            response.write(b"HTTP/1.1 400 Bad Request\r\n")
            response.write(b"Content-Type: text/plain\r\n")
            response.write(b"Content-Length: " + str(len(response_body)).encode() + b"\r\n")
            response.write(b"\r\n")
            response.write(response_body)
            return

        # Security: HTML escaping to prevent XSS
        escaped_username = html.escape(username)

        # Construct the response
        response_body = f"Hello {escaped_username}!".encode('utf-8')

        # Send the response
        response.write(b"HTTP/1.1 200 OK\r\n")
        response.write(b"Content-Type: text/html\r\n")
        response.write(b"Content-Length: " + str(len(response_body)).encode() + b"\r\n")
        response.write(b"\r\n")
        response.write(response_body)
    else:
        # Handle missing username
        response_body = b"Please provide a username."
        response.write(b"HTTP/1.1 400 Bad Request\r\n")
        response.write(b"Content-Type: text/plain\r\n")
        response.write(b"Content-Length: " + str(len(response_body)).encode() + b"\r\n")
        response.write(b"\r\n")
        response.write(response_body)


# Example usage (for testing - replace with your actual HTTP server)
if __name__ == '__main__':
    # Simulate a request
    request_body = b"username=TestUser"
    request_stream = io.BytesIO(request_body)
    response_stream = io.BytesIO()

    http_hello_page(request_stream, response_stream)

    # Print the response
    print(response_stream.getvalue().decode('utf-8'))

import io

