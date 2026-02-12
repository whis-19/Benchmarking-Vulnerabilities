import cgi
import html
import hashlib
import os
import secrets
import time
from typing import IO
from urllib.parse import urlparse

# Security: Rate limiting (simple in-memory example)
login_attempts = {}  # username: [timestamps]
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 60

# Security: Allowed file extensions (example)
ALLOWED_FILE_EXTENSIONS = {".txt", ".pdf", ".jpg", ".jpeg", ".png"}

# Security: Allowed domains/IPs (example - should be configurable)
ALLOWED_DOMAINS = {"example.com", "127.0.0.1"}  # Add your allowed domains

# Security:  Salt length for password hashing (should be long and random)
SALT_LENGTH = 16

def is_valid_domain(url: str) -> bool:
    """
    Validates that a URL's domain is in the allowlist.

    Args:
        url: The URL to validate.

    Returns:
        True if the domain is allowed, False otherwise.
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname is None:
            return False  # Or handle the case where there's no hostname appropriately
        return hostname in ALLOWED_DOMAINS
    except Exception:
        return False  # Handle parsing errors as invalid

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes a filename to prevent path traversal and other attacks.

    Args:
        filename: The filename to sanitize.

    Returns:
        The sanitized filename.
    """
    # Remove any characters that are not alphanumeric, underscores, or periods
    sanitized_filename = "".join(c for c in filename if c.isalnum() or c in "._-")
    # Prevent path traversal
    sanitized_filename = sanitized_filename.replace("..", "")
    return sanitized_filename

def is_allowed_file_extension(filename: str) -> bool:
    """
    Checks if a file extension is in the allowlist.

    Args:
        filename: The filename to check.

    Returns:
        True if the extension is allowed, False otherwise.
    """
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_FILE_EXTENSIONS

def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """Hashes a password using SHA-256 with a salt.

    Args:
        password: The password to hash.
        salt: Optional salt to use. If None, a new salt is generated.

    Returns:
        A tuple containing the hexadecimal representation of the salt and the hashed password.
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_LENGTH)  # Generate a random salt

    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return salt.hex(), hashed_password


def verify_password(password: str, salt_hex: str, hashed_password: str) -> bool:
    """Verifies a password against a stored hash.

    Args:
        password: The password to verify.
        salt_hex: The hexadecimal representation of the salt used to hash the password.
        hashed_password: The stored hash of the password.

    Returns:
        True if the password is correct, False otherwise.
    """
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False  # Invalid salt

    _, new_hashed_password = hash_password(password, salt)
    return new_hashed_password == hashed_password


def rate_limit(username: str) -> bool:
    """
    Implements rate limiting for login attempts.

    Args:
        username: The username attempting to log in.

    Returns:
        True if the user is allowed to attempt a login, False otherwise.
    """
    now = time.time()
    if username not in login_attempts:
        login_attempts[username] = []

    # Remove old attempts
    login_attempts[username] = [
        ts for ts in login_attempts[username] if ts > now - LOGIN_WINDOW_SECONDS
    ]

    if len(login_attempts[username]) >= MAX_LOGIN_ATTEMPTS:
        return False  # Rate limited
    else:
        login_attempts[username].append(now)
        return True


def http_hello_page(request: IO[bytes], response: IO[bytes]) -> None:
    """
    Handles an HTTP request, extracts the username, and sends a personalized greeting.

    Args:
        request: A file stream containing the HTTP request.
        response: A file stream to write the HTTP response to.
    """

    form = cgi.FieldStorage(fp=request.makefile('r', encoding='utf-8'), environ={'REQUEST_METHOD': 'POST'})

    if 'username' in form:
        username = form['username'].value

        # Security: Input validation and sanitization (stringent allowlist)
        if not isinstance(username, str) or not all(c.isalnum() or c in "._-" for c in username):
            response_body = "Invalid username.  Only alphanumeric characters, underscores, periods, and hyphens are allowed."
            response_code = "400 Bad Request"  # Indicate a client error
        else:
            # Security: HTML escaping to prevent XSS
            escaped_username = html.escape(username)
            response_body = f"Hello {escaped_username}!"
            response_code = "200 OK"

    else:
        response_body = "Please provide a username."
        response_code = "400 Bad Request"

    response_text = f"""HTTP/1.1 {response_code}\r\nContent-Type: text/html\r\n\r\n
    <!DOCTYPE html>
    <html>
    <head>
        <title>Greeting</title>
    </head>
    <body>
        <h1>{response_body}</h1>
    </body>
    </html>
    """

    response.write(response_text.encode('utf-8'))


if __name__ == '__main__':
    # Example usage (for testing - replace with a proper HTTP server)
    # Create a dummy request
    request_data = b"Content-Type: application/x-www-form-urlencoded\r\n\r\nusername=TestUser123"
    request_file = open("request.txt", "wb")
    request_file.write(request_data)
    request_file.close()

    with open("request.txt", "rb") as req_file, open("response.txt", "wb") as resp_file:
        http_hello_page(req_file, resp_file)

    print("Response written to response.txt")

    # Example of password hashing and verification
    password = "my_secret_password"
    salt, hashed_password = hash_password(password)
    print(f"Salt: {salt}")
    print(f"Hashed password: {hashed_password}")

    is_correct = verify_password(password, salt, hashed_password)
    print(f"Password verification: {is_correct}")

    is_correct = verify_password("wrong_password", salt, hashed_password)
    print(f"Password verification (wrong password): {is_correct}")

    # Example of rate limiting
    username = "testuser"
    for i in range(MAX_LOGIN_ATTEMPTS + 2):
        if rate_limit(username):
            print(f"Login attempt {i+1} allowed")
        else:
            print(f"Login attempt {i+1} rate limited")
            break

    # Example of filename sanitization
    filename = "../../../etc/passwd.txt"
    sanitized_filename = sanitize_filename(filename)
    print(f"Original filename: {filename}")
    print(f"Sanitized filename: {sanitized_filename}")

    # Example of file extension validation
    filename = "image.png"
    is_allowed = is_allowed_file_extension(filename)
    print(f"File extension {filename} allowed: {is_allowed}")

    filename = "script.exe"
    is_allowed = is_allowed_file_extension(filename)
    print(f"File extension {filename} allowed: {is_allowed}")

    # Example of domain validation
    url = "https://example.com/path"
    is_valid = is_valid_domain(url)
    print(f"Domain {url} allowed: {is_valid}")

    url = "https://malicious.com/path"
    is_valid = is_valid_domain(url)
    print(f"Domain {url} allowed: {is_valid}")

    os.remove("request.txt") # Clean up the dummy request file

