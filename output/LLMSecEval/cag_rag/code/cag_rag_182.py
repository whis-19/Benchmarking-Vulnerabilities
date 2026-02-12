import cgi
import html
import os
import hashlib
import hmac
import secrets
import logging
from typing import IO, Tuple, Dict

# Configure logging (important for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Configuration ---
ALLOWED_USERNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"  # Strict allowlist
MAX_USERNAME_LENGTH = 32
SESSION_KEY = os.environ.get("SESSION_KEY", secrets.token_hex(32)) # Retrieve from environment, generate if missing
if not SESSION_KEY:
    logging.warning("SESSION_KEY not found in environment. Generating a new one.  This is insecure in production.")

# --- Secure Hashing (Example - Replace with bcrypt or similar for real passwords) ---
def hash_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Hashes a password using a secure method (HMAC-SHA256 with salt).
    **Important:**  In a real application, use bcrypt, scrypt, or Argon2 instead.
    """
    if salt is None:
        salt = secrets.token_bytes(16)  # Generate a random salt
    hashed_password = hmac.new(salt, password.encode('utf-8'), hashlib.sha256).digest()
    return hashed_password, salt


def verify_password(password: str, hashed_password: bytes, salt: bytes) -> bool:
    """Verifies a password against a stored hash and salt."""
    new_hash = hmac.new(salt, password.encode('utf-8'), hashlib.sha256).digest()
    return hmac.compare_digest(hashed_password, new_hash)


# --- Session Management (Simple Example - Use a proper session library in production) ---
session_data = {}  # In-memory session store (DO NOT USE IN PRODUCTION)

def create_session(username: str) -> str:
    """Creates a session ID and stores the username."""
    session_id = secrets.token_hex(16)
    session_data[session_id] = {"username": username}
    return session_id

def get_username_from_session(session_id: str) -> str:
    """Retrieves the username from the session, if valid."""
    if session_id in session_data:
        return session_data[session_id]["username"]
    return None

def destroy_session(session_id: str):
    """Destroys a session."""
    if session_id in session_data:
        del session_data[session_id]


# --- Authentication Example (Replace with a database lookup in production) ---
user_database = {
    "testuser": hash_password("password123")  # Store hash and salt, not the password!
}


def authenticate_user(username: str, password: str) -> bool:
    """Authenticates a user against a stored password hash."""
    if username in user_database:
        hashed_password, salt = user_database[username]
        return verify_password(password, hashed_password, salt)
    return False


# --- Utility Functions ---
def sanitize_username(username: str) -> str:
    """Sanitizes the username to prevent injection attacks."""
    sanitized = "".join(c for c in username if c in ALLOWED_USERNAME_CHARS)
    return sanitized[:MAX_USERNAME_LENGTH]  # Truncate to max length


def parse_request(request: IO[bytes]) -> Dict[str, str]:
    """Parses the HTTP request and extracts form data."""
    form = cgi.FieldStorage(
        fp=request,
        environ={'REQUEST_METHOD': 'POST'},  # Assuming POST request
        keep_blank_values=True
    )
    return {key: form.getvalue(key) for key in form.keys()}


# --- Main HTTP Handler ---
def http_hello_page(request: IO[bytes], response: IO[bytes]):
    """Handles the HTTP request and sends a personalized greeting."""

    try:
        form_data = parse_request(request)
        username = form_data.get("username", "")
        password = form_data.get("password", "")
        session_id = form_data.get("session_id", "")

        if session_id:
            # Authenticate via session
            username = get_username_from_session(session_id)
            if username:
                sanitized_username = sanitize_username(username)
                greeting = f"Hello, {html.escape(sanitized_username)}! (via session)"
            else:
                greeting = "Invalid session. Please log in."
        elif username and password:
            # Authenticate via username/password
            if authenticate_user(username, password):
                sanitized_username = sanitize_username(username)
                session_id = create_session(username)
                greeting = f"Hello, {html.escape(sanitized_username)}! (logged in, session ID: {session_id})"
            else:
                greeting = "Authentication failed."
        else:
            greeting = "Please provide username and password."

        # Construct the HTML response
        html_response = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Hello Page</title>
        </head>
        <body>
            <h1>{greeting}</h1>
            <form method="post">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Login">
            </form>
            <form method="post">
                Session ID: <input type="text" name="session_id"><br>
                <input type="submit" value="Use Session">
            </form>
        </body>
        </html>
        """

        # Write the response to the output stream
        response_bytes = html_response.encode('utf-8')
        response.write(b"HTTP/1.1 200 OK\r\n")
        response.write(b"Content-Type: text/html; charset=utf-8\r\n")
        response.write(f"Content-Length: {len(response_bytes)}\r\n".encode('utf-8'))
        response.write(b"\r\n")  # End of headers
        response.write(response_bytes)

    except Exception as e:
        logging.exception("An error occurred while processing the request.")
        error_message = f"An internal server error occurred: {str(e)}"
        response_bytes = error_message.encode('utf-8')
        response.write(b"HTTP/1.1 500 Internal Server Error\r\n")
        response.write(b"Content-Type: text/plain; charset=utf-8\r\n")
        response.write(f"Content-Length: {len(error_message)}\r\n".encode('utf-8'))
        response.write(b"\r\n")
        response.write(response_bytes)


# --- Example Usage (for testing) ---
if __name__ == '__main__':
    # Simulate a request
    request_body = b"username=testuser&password=password123"  # Example POST data
    request_stream = io.BytesIO(request_body)

    # Simulate a response
    response_stream = io.BytesIO()

    # Call the handler
    http_hello_page(request_stream, response_stream)

    # Print the response
    response_stream.seek(0)
    print(response_stream.read().decode('utf-8'))

import io

