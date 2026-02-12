import functools
import html
import hashlib
import os
from typing import Callable, Dict

# In-memory URL mapping (replace with a database in a real application)
url_mapping: Dict[str, Callable] = {}


def route(url: str) -> Callable:
    """
    A decorator that maps a URL to a function.

    Args:
        url: The URL to map to the function.

    Returns:
        A decorator function.
    """

    def decorator(func: Callable) -> Callable:
        """
        The actual decorator function.

        Args:
            func: The function to decorate.

        Returns:
            The decorated function.
        """
        url_mapping[url] = func

        @functools.wraps(func)  # Preserve original function's metadata
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

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
    escaped_username = escape(username)  # Escape user input!
    return f"Hello, {escaped_username}!"


# Example usage (simulating a request)
def handle_request(url: str) -> str:
    """
    Handles a request by looking up the URL in the mapping and calling the
    associated function.

    Args:
        url: The URL of the request.

    Returns:
        The response from the function, or an error message if the URL is not found.
    """
    # Simple URL parsing (replace with a proper framework's routing mechanism)
    parts = url.split("/")
    if len(parts) >= 3 and parts[1] == "hello":
        username = parts[2]
        if "/hello/<username>" in url_mapping:
            return url_mapping["/hello/<username>"](username)
        else:
            return "Error: URL not found."
    else:
        return "Error: URL not found."


# Authentication example (using password hashing)
def hash_password(password: str) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 100000
    )  # 100k iterations
    return salt.hex() + ":" + hashed_password.hex()  # Store salt and hash


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a password against a stored hash (salt:hash)."""
    try:
        salt, hashed_password = stored_hash.split(":")
        salt_bytes = bytes.fromhex(salt)
        hashed_password_bytes = bytes.fromhex(hashed_password)
        new_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt_bytes, 100000
        )
        return new_hash == hashed_password_bytes
    except ValueError:
        return False  # Invalid stored hash format


# Example usage
if __name__ == "__main__":
    # Simulate a request
    request_url = "/hello/World<script>alert('XSS')</script>"
    response = handle_request(request_url)
    print(f"Response for {request_url}: {response}")

    # Authentication example
    password = "my_secret_password"
    hashed = hash_password(password)
    print(f"Hashed password: {hashed}")

    is_valid = verify_password(password, hashed)
    print(f"Password is valid: {is_valid}")

    is_valid_wrong = verify_password("wrong_password", hashed)
    print(f"Wrong password is valid: {is_valid_wrong}")

