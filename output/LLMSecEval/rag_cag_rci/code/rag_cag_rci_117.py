import functools
import html
import hashlib
import os
from typing import Callable, Dict
from urllib.parse import quote

# In-memory URL mapping (replace with a database in a real application)
url_map: Dict[str, Callable] = {}


def route(url: str) -> Callable:
    """
    Decorator to map a URL to a function.

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

        url_map[url] = func
        @functools.wraps(func)  # Preserve original function's metadata
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper

    return decorator


def escape(text: str) -> str:
    """
    Escapes special characters to HTML-safe sequences.

    Args:
        text: The text to escape.

    Returns:
        The escaped text.
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


def dispatch_request(url: str) -> str:
    """
    Dispatches a request to the appropriate handler based on the URL.

    Args:
        url: The URL to dispatch.

    Returns:
        The response from the handler, or an error message if no handler is found.
    """
    # Basic URL sanitization (more robust validation is needed in production)
    if not isinstance(url, str):
        return "Error: Invalid URL format."

    # Simple URL matching (replace with a more robust routing library in production)
    for registered_url, handler in url_map.items():
        # Replace <username> with a regex pattern
        if "<username>" in registered_url:
            prefix = registered_url.split("<username>")[0]
            if url.startswith(prefix):
                username = url[len(prefix):]
                # URL encode the username to prevent injection
                encoded_username = quote(username)
                return handler(encoded_username)
        elif url == registered_url:
            return handler()

    return "Error: URL not found."


# Example usage:
if __name__ == "__main__":
    # Simulate a request to /hello/world
    url = "/hello/world"
    response = dispatch_request(url)
    print(response)  # Output: Hello, world!

    # Simulate a request to /hello/<script>alert('XSS')</script>
    url = "/hello/<script>alert('XSS')</script>"
    response = dispatch_request(url)
    print(response)  # Output: Hello, &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;!

    # Simulate a request to an invalid URL
    url = "/invalid_url"
    response = dispatch_request(url)
    print(response)  # Output: Error: URL not found.

    # Example of password hashing (authentication context)
    password = "my_secret_password"
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Recommended number of iterations
    )

    # Store salt and hashed_password in the database (salt is needed for verification)
    # In a real application, you would retrieve the salt and hashed password from the database
    # and compare the hash of the entered password with the stored hash.

    # Example of password verification
    entered_password = "my_secret_password"
    entered_hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        entered_password.encode('utf-8'),
        salt,
        100000
    )

    if entered_hashed_password == hashed_password:
        print("Authentication successful!")
    else:
        print("Authentication failed.")


# Example of Content Security Policy (CSP) -  This would be set in the HTTP header
# "Content-Security-Policy: default-src 'self'; script-src 'self' https://example.com; object-src 'none';"

# Further considerations for a production environment:

# 1.  Use a proper web framework (Flask, Django) for routing, request handling, and templating.
# 2.  Implement CSRF protection using the framework's built-in mechanisms.
# 3.  Use a database to store user data and URL mappings.
# 4.  Implement proper authentication and authorization.
# 5.  Use HTTPS and validate SSL/TLS certificates.
# 6.  Implement rate limiting to prevent brute-force attacks.
# 7.  Implement input validation and sanitization on all user inputs.
# 8.  Use a secure session management mechanism.
# 9.  Implement logging and monitoring.
# 10. Regularly update dependencies to patch security vulnerabilities.

