import functools
import html
from typing import Callable, Dict

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
            The wrapper function that is executed when the URL is accessed.

            Args:
                *args: Positional arguments passed to the original function.
                **kwargs: Keyword arguments passed to the original function.

            Returns:
                The return value of the original function.
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


@route("/hello/<username>")
def hello(username: str) -> str:
    """
    Returns a greeting string with the username.

    Args:
        username: The username to greet.

    Returns:
        A greeting string.
    """
    escaped_username = escape(username)  # Escape the username for security
    return f"Hello, {escaped_username}!"


def handle_request(url: str) -> str:
    """
    Handles a request by looking up the URL in the mapping and calling the
    corresponding function.

    Args:
        url: The URL to handle.

    Returns:
        The response from the function, or an error message if the URL is not found.
    """
    for registered_url, func in url_mapping.items():
        # Simple URL matching (can be improved with regex for more complex patterns)
        if "<" in registered_url and ">" in registered_url:
            # Extract the parameter name from the URL
            param_name = registered_url[
                registered_url.find("<") + 1 : registered_url.find(">")
            ]
            base_url = registered_url[: registered_url.find("<")]

            if url.startswith(base_url):
                username = url[len(base_url) :]
                return func(username)  # Call the function with the username
        elif url == registered_url:
            return func()  # Call the function with no arguments

    return "Error: URL not found."


# Example usage:
if __name__ == "__main__":
    # Simulate a request to /hello/world
    response = handle_request("/hello/world")
    print(response)  # Output: Hello, world!

    # Simulate a request to /hello/<script>alert("XSS")</script>
    response = handle_request("/hello/<script>alert(\"XSS\")</script>")
    print(response)  # Output: Hello, &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;!

    # Simulate a request to an unknown URL
    response = handle_request("/goodbye/world")
    print(response)  # Output: Error: URL not found.

