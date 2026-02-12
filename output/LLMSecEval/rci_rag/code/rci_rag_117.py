import html
import re
from urllib.parse import urlparse
import logging
import json  # For context-aware escaping example

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Dictionary to store URL mappings
url_mapping = {}

def route(url):
    """
    Decorator to map a URL to a function.

    Args:
        url (str): The URL to map.
    """
    def decorator(func):
        """
        The actual decorator function.

        Args:
            func (callable): The function to be decorated.
        """
        # Validate the URL (basic check, can be expanded)
        if not isinstance(url, str):
            raise TypeError("URL must be a string.")

        # Sanitize URL (example: remove leading/trailing spaces)
        url = url.strip()

        # Store the mapping
        url_mapping[url] = func
        return func  # Return the original function
    return decorator


class InvalidUsernameError(Exception):
    """Custom exception for invalid usernames."""
    pass


@route("/hello/<username>")
def hello(username):
    """
    Returns a greeting with the escaped username.

    Args:
        username (str): The username to greet.

    Returns:
        str: A greeting string.

    Raises:
        InvalidUsernameError: If the username is invalid.
    """
    # Validate username (example: alphanumeric and limited length)
    # Consider the potential for Regular Expression Denial of Service (ReDoS) attacks
    # if using very complex regexes.  See OWASP for more information.
    if not re.match(r"^[a-zA-Z0-9]{1,20}$", username):
        logging.warning(f"Invalid username format: {username}")
        raise InvalidUsernameError(f"Invalid username format: Username '{username}' must be alphanumeric and 1-20 characters long.")

    # Escape the username for HTML output to prevent XSS
    escaped_username = html.escape(username)
    return f"Hello, {escaped_username}!"


def process_request(url):
    """
    Processes a URL request and calls the appropriate function.

    Args:
        url (str): The requested URL.

    Returns:
        str: The response from the mapped function, or an error message.
    """
    try:
        # Parse the URL to handle potential issues with subdomains or other components
        parsed_url = urlparse(url)

        # Basic validation of the URL scheme and netloc (hostname)
        if parsed_url.scheme not in ('http', 'https', ''):  # Allow empty scheme for relative URLs in some contexts
            logging.warning(f"Invalid URL scheme: {parsed_url.scheme}")
            return "Invalid URL scheme."

        # Example: Check the hostname against a whitelist (important for SSRF prevention)
        # allowed_hosts = ['example.com', 'localhost']
        # if parsed_url.netloc and parsed_url.netloc not in allowed_hosts:
        #     logging.warning(f"Invalid hostname: {parsed_url.netloc}")
        #     return "Invalid hostname."

        # Find a matching route
        for route_pattern, func in url_mapping.items():
            # Simple pattern matching (can be improved with regex)
            if "<username>" in route_pattern:
                base_route = route_pattern.replace("<username>", "")
                if url.startswith(base_route):
                    username = url[len(base_route):]
                    try:
                        return func(username)
                    except InvalidUsernameError as e:
                        logging.error(f"Error processing username: {e}")
                        return str(e)  # Return the error message
                    except Exception as e:
                        logging.exception(f"Unexpected error processing request: {e}") # Log the full exception
                        return "500 Internal Server Error" # Generic error for unexpected issues
            elif url == route_pattern:
                return func()  # Call the function if the URL matches exactly

        logging.info(f"URL not found: {url}")
        return "404 Not Found"

    except Exception as e:
        logging.exception(f"Unexpected error processing request: {e}")
        return "500 Internal Server Error"

# Example usage:
if __name__ == '__main__':
    # Simulate a request
    request_url = "/hello/Alice123"
    response = process_request(request_url)
    print(f"Request URL: {request_url}")
    print(f"Response: {response}")

    request_url_malicious = "/hello/<script>alert('XSS')</script>"
    response_malicious = process_request(request_url_malicious)
    print(f"Request URL: {request_url_malicious}")
    print(f"Response: {response_malicious}")

    request_url_invalid = "ftp://example.com/hello/Bob"
    response_invalid = process_request(request_url_invalid)
    print(f"Request URL: {request_url_invalid}")
    print(f"Response: {response_invalid}")

    request_url_long_username = "/hello/ThisIsAVeryLongUsernameThatExceedsTheLimit"
    response_long_username = process_request(request_url_long_username)
    print(f"Request URL: {request_url_long_username}")
    print(f"Response: {response_long_username}")

    # Context-aware escaping example (demonstration - not directly used in this code)
    # If inserting data into a JavaScript string:
    data = "<script>alert('XSS')</script>"
    js_string = json.dumps(data)  # Use json.dumps for proper escaping
    print(f"Escaped for JavaScript: {js_string}")

    # If inserting data into a CSS style:
    # CSS escaping is complex and context-dependent.  Consider using a dedicated
    # CSS escaping library or carefully validating and sanitizing the input.
    # Example (very basic and incomplete):
    css_string = data.replace("<", r"\<").replace(">", r"\>") # Incomplete and not recommended for production
    print(f"Escaped for CSS (basic example - INCOMPLETE): {css_string}")


    # --- Further Security Considerations (Not Implemented in this Example - REQUIRES FURTHER CONFIGURATION) ---
    # 1. Content Security Policy (CSP):  Configure your web server to send CSP headers
    #    to control the sources from which the browser is allowed to load resources.
    #    Example:  "default-src 'self';"  (Requires web server configuration)

    # 2. Rate Limiting: Implement rate limiting to prevent brute-force attacks or
    #    denial-of-service attacks.  This can be done at the web server level (e.g., using
    #    nginx's limit_req module) or within the application code. (Requires further implementation)

    # 3. CSRF Protection: If the application involves state-changing operations (e.g.,
    #    submitting forms), implement Cross-Site Request Forgery (CSRF) protection.
    #    This typically involves including a unique, unpredictable token in forms and
    #    verifying it on the server-side. (Requires further implementation)

