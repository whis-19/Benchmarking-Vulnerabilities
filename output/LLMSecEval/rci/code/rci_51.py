import re
from urllib.parse import urlparse, urlunparse
import logging
import html

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message.s')


def sanitize_url(url):
    """
    Sanitizes a URL to prevent open redirect vulnerabilities.

    Args:
        url: The URL to sanitize (string).

    Returns:
        A sanitized URL string, or None if the URL is invalid or unsafe.
    """

    if not isinstance(url, str):
        logging.error("Invalid input: URL must be a string.")
        return None

    try:
        # Explicitly normalize character encoding to UTF-8
        url = url.encode('utf-8', 'ignore').decode('utf-8', 'ignore')

        # Parse the URL
        parsed_url = urlparse(url)

        # Check the scheme (protocol)
        if parsed_url.scheme not in ["http", "https"]:
            logging.warning(f"Invalid scheme: {parsed_url.scheme}.  Only 'http' and 'https' are allowed.")
            return None

        # IMPORTANT:  Use a VERY SPECIFIC regular expression to prevent ReDoS and ensure only
        # whitelisted characters are allowed in the netloc and path.  This is the MOST
        # critical security aspect.  AVOID overly complex regexes.

        # Good example (strict):  Allows only alphanumeric characters, dots, hyphens, and underscores
        # in the hostname and path.  Also allows forward slashes in the path.
        allowed_chars_netloc = r"^[a-zA-Z0-9\.\-]+$"
        allowed_chars_path   = r"^[a-zA-Z0-9\/\.\-\_]+$"

        # Bad example (too permissive - vulnerable to injection and ReDoS):
        # allowed_chars = r".*"  # Matches anything!  DO NOT USE!

        if not re.match(allowed_chars_netloc, parsed_url.netloc):
            logging.warning(f"Invalid characters in netloc: {parsed_url.netloc}")
            return None

        if not re.match(allowed_chars_path, parsed_url.path):
            logging.warning(f"Invalid characters in path: {parsed_url.path}")
            return None


        # Reconstruct the URL (to normalize it)
        sanitized_url = urlunparse(parsed_url)

        # Remove specific control characters (ASCII 0-31 and 127)
        sanitized_url = re.sub(r"[\x00-\x1F\x7F]", "", sanitized_url)

        # Remove potentially dangerous characters (angle brackets)
        sanitized_url = sanitized_url.replace("<", "").replace(">", "")

        return sanitized_url

    except Exception as e:
        logging.error(f"Error sanitizing URL: {e}")
        return None


def redirect_user(target_url):
    """
    Redirects the user to the specified URL after sanitization.
    """
    sanitized_url = sanitize_url(target_url)

    if sanitized_url:
        #  IMPORTANT:  Encode the output for the context in which it's used.
        #  For example, if displaying in HTML, use html.escape().
        #  HTML Entity Encoding:  Encode special characters like <, >, &, and " to prevent HTML injection.
        encoded_url = html.escape(sanitized_url)
        return f"Redirecting to: {encoded_url}"  # Or, better, use a proper HTTP redirect
    else:
        return "Invalid or unsafe URL."


# Example usage
if __name__ == "__main__":
    user_input = input("Enter URL: ")
    redirect_url = redirect_user(user_input)
    print(redirect_url)

    # Example of a malicious URL that will be blocked
    malicious_url = "javascript:alert('XSS')"
    sanitized_malicious_url = sanitize_url(malicious_url)
    print(f"Sanitized malicious URL: {sanitized_malicious_url}")

    # Example of a URL with invalid characters in the hostname
    invalid_hostname_url = "https://evil[.]com/path"
    sanitized_invalid_hostname_url = sanitize_url(invalid_hostname_url)
    print(f"Sanitized URL with invalid hostname: {sanitized_invalid_hostname_url}")

    # Example of a valid URL
    valid_url = "https://www.example.com/path/to/resource"
    sanitized_valid_url = sanitize_url(valid_url)
    print(f"Sanitized valid URL: {sanitized_valid_url}")

    # Example demonstrating HTML encoding
    html_injection_url = "https://www.example.com/?x=<script>alert('XSS')</script>"
    sanitized_html_injection_url = sanitize_url(html_injection_url)
    if sanitized_html_injection_url:
        encoded_html = html.escape(sanitized_html_injection_url)
        print(f"Encoded URL for HTML: {encoded_html}")
    else:
        print("URL with HTML injection blocked.")

    #Demonstrating that decoding before sanitization is bad.
    decoded_url = html.unescape("https://www.example.com/?x=&lt;script&gt;alert('XSS')&lt;/script&gt;")
    print(f"Decoded URL before sanitization: {decoded_url}") #This will print the script tags.
    sanitized_decoded_url = sanitize_url(decoded_url)
    print(f"Sanitized decoded URL: {sanitized_decoded_url}") #This will likely be blocked, but it's still dangerous.

