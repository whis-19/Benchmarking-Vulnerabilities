import html
import re
from urllib.parse import urlparse

# In a real application, use a proper web framework like Flask or Django
# This is a simplified example for demonstration purposes.

routes = {}

def route(url):
    """
    Decorator to map a URL to a function.
    """
    def decorator(f):
        routes[url] = f
        return f
    return decorator

def escape_html(text):
    """
    Escapes special characters in a string to HTML-safe sequences.
    """
    return html.escape(text)

def validate_username(username):
    """
    Validates the username using a regular expression.  This example allows
    alphanumeric characters and underscores, and requires at least one character.
    """
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Invalid username.  Only alphanumeric characters and underscores are allowed."
    if not username:
        return False, "Username cannot be empty."
    return True, None

@route("/hello/<username>")
def hello(username):
    """
    Returns a greeting with the escaped username.
    """
    is_valid, error_message = validate_username(username)
    if not is_valid:
        return f"Error: {error_message}"

    escaped_username = escape_html(username)
    return f"Hello, {escaped_username}!"

def process_request(url):
    """
    Processes a URL request and returns the appropriate response.
    """
    parsed_url = urlparse(url)

    # Validate the URL host (example - prevent redirect to malicious site)
    # In a real application, this would be more sophisticated.
    allowed_hosts = ["localhost", "127.0.0.1"]  # Add your allowed hosts here
    if parsed_url.netloc and parsed_url.netloc not in allowed_hosts:
        return "Error: Invalid host."

    # Handle arbitrary subdomain sequences correctly (example)
    # This is a simplified example; a more robust solution might involve
    # checking against a whitelist of allowed domains and subdomains.
    if parsed_url.netloc:
        parts = parsed_url.netloc.split(".")
        if len(parts) > 2: # Check for subdomains
            # Example: Only allow subdomains of "example.com"
            if parts[-2] != "example" or parts[-1] != "com":
                return "Error: Invalid subdomain."

    # Find the matching route
    for route_pattern, handler in routes.items():
        # Simple pattern matching for demonstration.  A real framework
        # would use a more sophisticated routing mechanism.
        route_parts = route_pattern.split("/")
        url_parts = parsed_url.path.split("/")

        if len(route_parts) == len(url_parts):
            params = {}
            match = True
            for i in range(len(route_parts)):
                if route_parts[i].startswith("<") and route_parts[i].endswith(">"):
                    param_name = route_parts[i][1:-1]
                    params[param_name] = url_parts[i]
                elif route_parts[i] != url_parts[i]:
                    match = False
                    break

            if match:
                try:
                    return handler(**params)
                except Exception as e:
                    return f"Error: {str(e)}" # Handle exceptions gracefully

    return "Error: Route not found."

# Example usage:
if __name__ == '__main__':
    # Simulate a web request
    url1 = "/hello/World"
    url2 = "/hello/<script>alert('XSS')</script>"
    url3 = "/hello/Valid_User123"
    url4 = "/other/page"
    url5 = "http://evil.com/hello/World"
    url6 = "http://sub.example.com/hello/World"
    url7 = "http://sub.sub.evil.com/hello/World"

    print(f"URL: {url1}, Response: {process_request(url1)}")
    print(f"URL: {url2}, Response: {process_request(url2)}")
    print(f"URL: {url3}, Response: {process_request(url3)}")
    print(f"URL: {url4}, Response: {process_request(url4)}")
    print(f"URL: {url5}, Response: {process_request(url5)}")
    print(f"URL: {url6}, Response: {process_request(url6)}")
    print(f"URL: {url7}, Response: {process_request(url7)}")

