import functools
import html
import hashlib
import os
from typing import Callable, Dict
from urllib.parse import quote

# In-memory URL mapping (replace with a proper routing mechanism in a real application)
url_map: Dict[str, Callable] = {}


def route(url: str) -> Callable:
    """
    Decorator to map a URL to a function.

    Args:
        url: The URL to map to the function.

    Returns:
        A decorator function.
    """

    def decorator(f: Callable) -> Callable:
        """
        The actual decorator function.

        Args:
            f: The function to decorate.

        Returns:
            The decorated function.
        """
        url_map[url] = f
        @functools.wraps(f)  # Preserve original function's metadata
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper

    return decorator


def escape(text: str) -> str:
    """
    Escapes special characters in a string to HTML-safe sequences.

    Args:
        text: The string to escape.

    Returns:
        The escaped string.
    """
    return html.escape(text)


@route("/hello/<username>")
def hello(username: str) -> str:
    """
    Returns a greeting with the escaped username.

    Args:
        username: The username to greet.

    Returns:
        A string with the greeting.
    """
    escaped_username = escape(username)
    return f"Hello, {escaped_username}!"


def handle_request(url: str) -> str:
    """
    Handles a request by routing it to the appropriate function.

    Args:
        url: The URL of the request.

    Returns:
        The response from the function, or an error message if the URL is not found.
    """
    # Basic URL sanitization (more robust validation is needed in production)
    if not isinstance(url, str):
        return "Invalid URL"

    # Simple URL matching (replace with a proper routing library)
    for route_pattern, handler in url_map.items():
        if "<username>" in route_pattern:
            base_route = route_pattern.split("<username>")[0]
            if url.startswith(base_route):
                username = url[len(base_route):]
                return handler(username)
        elif route_pattern == url:
            return handler()

    return "404 Not Found"


# Example usage:
if __name__ == "__main__":
    # Simulate a request to /hello/World
    response = handle_request("/hello/World")
    print(response)  # Output: Hello, World!

    # Simulate a request to /hello/<script>alert('XSS')</script>
    response = handle_request("/hello/<script>alert('XSS')</script>")
    print(response)  # Output: Hello, &lt;script&gt;alert('XSS')&lt;/script&gt;!

    # Simulate a request to an unknown URL
    response = handle_request("/goodbye/World")
    print(response)  # Output: 404 Not Found


# --- Authentication related functions (as per preconditions) ---

def hash_password(password: str) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Iterations (adjust as needed)
    )
    # Store the salt and hashed password together (e.g., salt:hashed_password)
    return f"{salt.hex()}:{hashed_password.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a password against a stored hash (salt:hashed_password)."""
    try:
        salt_hex, hashed_password_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        hashed_password = bytes.fromhex(hashed_password_hex)

        computed_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        return computed_hash == hashed_password
    except ValueError:
        # Handle cases where the stored hash is invalid
        return False


# Example usage of authentication functions:
if __name__ == "__main__":
    # Example password hashing and verification
    password = "my_secret_password"
    hashed_password = hash_password(password)
    print(f"Hashed password: {hashed_password}")

    is_valid = verify_password(password, hashed_password)
    print(f"Password is valid: {is_valid}")

    is_valid = verify_password("wrong_password", hashed_password)
    print(f"Password is valid (wrong password): {is_valid}")

