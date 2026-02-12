import functools
import html
import re
import logging
from typing import Callable, Dict, Optional
from urllib.parse import unquote

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Store the URL mappings
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

        url_mapping[url] = func  # Store the mapping

        @functools.wraps(func)  # Preserve original function's metadata
        def wrapper(*args, **kwargs):
            """
            Wrapper function to execute the original function.
            """
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


def validate_username(username: str) -> Optional[str]:
    """
    Validates and sanitizes the username.

    Args:
        username: The username to validate.

    Returns:
        The validated username, or None if the username is invalid.
    """
    if not isinstance(username, str):
        return None  # Reject non-string input

    if len(username) > 50:  # Limit username length
        return None

    if not re.match(r"^[a-zA-Z0-9_]+$", username):  # Allow only alphanumeric and underscore
        return None

    return username


@route("/hello/<username>")
def hello(username: str) -> str:
    """
    Returns a greeting string with the username.

    Args:
        username: The username to greet.

    Returns:
        A greeting string.
    """
    # Validate username *after* URL decoding
    validated_username = validate_username(username)
    if validated_username is None:
        return "400 Bad Request: Invalid username"

    escaped_username = escape(validated_username)  # Escape the username for security
    return f"Hello, {escaped_username}!"


def handle_request(url: str) -> str:
    """
    Handles a request by looking up the URL in the mapping and calling the
    corresponding function.

    Args:
        url: The URL to handle.

    Returns:
        The result of the function call, or an error message if the URL is not found.
    """
    url = unquote(url)  # Decode URL-encoded characters

    for registered_url, func in url_mapping.items():
        # Use regex for more robust URL matching
        # Example:  ^/hello/([a-zA-Z0-9_]+)$
        regex = "^" + registered_url.replace("<username>", "([a-zA-Z0-9_]+)") + "$"
        match = re.match(regex, url)

        if match:
            try:
                # Extract the parameter values from the URL
                params = match.groups()
                return func(*params)  # Call the function with the parameters
            except ValueError as e:
                logging.error(f"ValueError handling request: {e}")
                return "400 Bad Request: Invalid input"
            except Exception as e:
                logging.exception(f"Error handling request: {e}")  # Log the full exception
                return "500 Internal Server Error"


        elif url == registered_url:
            try:
                return func()  # Call the function with no arguments
            except Exception as e:
                logging.exception(f"Error handling request: {e}")
                return "500 Internal Server Error"

    return "404 Not Found"


if __name__ == "__main__":
    # Example usage:
    url = "/hello/World"
    response = handle_request(url)
    print(f"URL: {url}, Response: {response}")

    url = "/hello/<script>alert('XSS')</script>"
    response = handle_request(url)
    print(f"URL: {url}, Response: {response}")

    url = "/hello/Invalid!Username"
    response = handle_request(url)
    print(f"URL: {url}, Response: {response}")

    url = "/nonexistent"
    response = handle_request(url)
    print(f"URL: {url}, Response: {response}")

    url = "/hello/World/extra"  # Test for incorrect matching
    response = handle_request(url)
    print(f"URL: {url}, Response: {response}")

    url = "/hello/%2e%2e%2f%2e%2e%2fetc%2fpasswd" # Test path traversal
    response = handle_request(url)
    print(f"URL: {url}, Response: {response}")

    url = "/hello/ValidUsername"
    response = handle_request(url)
    print(f"URL: {url}, Response: {response}")

    url = "/hello/%56alidUsername"
    response = handle_request(url)
    print(f"URL: {url}, Response: {response}")

