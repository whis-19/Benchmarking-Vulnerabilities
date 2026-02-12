import re
import urllib.parse
import ssl
import socket
from html import escape
import logging
import certifi  # For CA bundle

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Compile the regular expression ONCE at module load time.  This is more efficient.
#  Adjust this regex to match your specific URL pattern.  Be as specific as possible.
#  Example:  r"^https://www\.example\.com/path/to/resource\?param1=value1&param2=.*$"
#  This example matches URLs starting with "https://www.example.com/path/to/resource?param1=value1&param2=" followed by any characters.
#  IMPORTANT:  The regex should be as restrictive as possible to prevent bypasses.
#  Using named capture groups for readability and maintainability.
URL_REGEX = re.compile(r"^https://www\.example\.com/products/(?P<product_id>[a-zA-Z0-9-]+)\?sort=(?P<sort_order>price|name)$")  # Example: Specific product URL

# Default redirect URL.  MUST be a valid and safe URL.
DEFAULT_REDIRECT_URL = "https://www.example.com/default"

# Allowed domains/IPs for redirects.  Use a set for fast lookups.
#  Consider using a more robust allowlisting mechanism, such as allowing specific paths or resources.
ALLOWED_DOMAINS = {"www.example.com", "example.com"}  # Add your allowed domains/IPs here
ALLOWED_DOMAINS_SET = frozenset(ALLOWED_DOMAINS) # Use frozenset for immutability and slight performance boost

def is_valid_url(url):
    """
    Validates the URL format and checks if the domain/IP is in the allowlist.
    """
    try:
        result = urllib.parse.urlparse(url)

        # Scheme Check: Explicitly check for HTTPS and reject anything else.
        if result.scheme != "https":
            logging.warning(f"Invalid scheme: {result.scheme}. HTTPS is required. URL: {url}")
            return False

        # Netloc Handling: Check against allowlist.
        netloc = result.netloc
        if ":" in netloc:  # Handle port numbers in netloc
            netloc = netloc.split(":")[0]

        if netloc not in ALLOWED_DOMAINS_SET:
            logging.warning(f"Domain/IP not in allowlist: {netloc}. URL: {url}")
            return False

        # Path Length Limit
        if len(result.path) > 2048:  # Example path length limit
            logging.warning(f"Path length exceeds maximum allowed. URL: {url}")
            return False

        # Query Parameter Validation (Example - adapt to your specific needs)
        query_params = urllib.parse.parse_qs(result.query)
        if "sort" in query_params:
            sort_value = query_params["sort"][0]  # Get the first value
            if sort_value not in ("price", "name"):
                logging.warning(f"Invalid sort parameter value: {sort_value}. URL: {url}")
                return False

        # Character Encoding Check (Basic example - can be expanded)
        try:
            url.encode('ascii')  # Check for non-ASCII characters
        except UnicodeEncodeError:
            logging.warning(f"URL contains non-ASCII characters. URL: {url}")
            return False

        # URL Normalization (before validation - important!)
        normalized_url = urllib.parse.urlunparse(urllib.parse.urlparse(url))
        if normalized_url != url:
            logging.info(f"URL was normalized from {url} to {normalized_url}")
            # Continue validation with the normalized URL, or reject.  For this example, we continue.
            url = normalized_url # Use the normalized URL for further processing

        return True

    except Exception as e:
        logging.error(f"URL parsing error: {e}. URL: {url}")
        return False

def sanitize_url(url):
    """
    Sanitizes the URL to prevent common injection attacks.
    This is a more robust example that performs both URL encoding and HTML encoding.
    Assumes the URL will be used in an HTML context.
    """
    # URL-encode the URL to escape special characters.  Important to do this *before* HTML encoding.
    url = urllib.parse.quote(url, safe=":/")  # Keep : and / safe for URL structure

    # HTML-encode the URL to prevent XSS
    url = escape(url)
    return url

def validate_ssl_certificate(hostname, port=443):
    """
    Validates the SSL/TLS certificate of the target host.
    """
    try:
        context = ssl.create_default_context(cafile=certifi.where())  # Load trusted CA certificates
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.do_handshake()
                cert = ssock.getpeercert()
                # Basic certificate validation (check expiry, common name)
                ssl.match_hostname(cert, hostname)  # Raises exception if hostname doesn't match

                # Example: Check certificate expiry
                # expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                # if expiry_date < datetime.datetime.now():
                #     logging.warning(f"SSL certificate expired on {expiry_date}")
                #     return False

                return True
    except Exception as e:
        logging.error(f"SSL certificate validation failed for {hostname}: {e}")
        return False

def get_safe_redirect_url(target_url):
    """
    Determines the redirect URL based on the target URL and the regular expression.
    """

    if not isinstance(target_url, str):
        logging.warning("Target URL must be a string.")
        return DEFAULT_REDIRECT_URL

    # Validate the target URL BEFORE sanitizing it.  Validation should be done on the original URL.
    if not is_valid_url(target_url):
        logging.warning(f"Invalid target URL: {target_url}")
        return DEFAULT_REDIRECT_URL

    # Match the target URL against the pre-compiled regular expression.  Match against the *original* URL, not the sanitized one.
    if not URL_REGEX.match(target_url):
        logging.warning(f"Target URL did not match regex: {target_url}")
        return DEFAULT_REDIRECT_URL  # Use the default redirect URL

    # Sanitize the target URL AFTER validation and regex matching.
    sanitized_target_url = sanitize_url(target_url)


    # Check SSL certificate
    parsed_url = urllib.parse.urlparse(sanitized_target_url)
    hostname = parsed_url.netloc.split(":")[0] if ":" in parsed_url.netloc else parsed_url.netloc
    if not validate_ssl_certificate(hostname):
        logging.warning(f"SSL certificate validation failed for {hostname}")
        return DEFAULT_REDIRECT_URL


    logging.info(f"Target URL matched regex: {target_url}. Redirecting to sanitized URL: {sanitized_target_url}")
    return sanitized_target_url  # Use the sanitized target URL as the redirect URL


# Example usage:
if __name__ == "__main__":
    # Test cases
    target_url1 = "https://www.example.com/products/widget-123?sort=price"  # Matches the example regex
    target_url2 = "https://www.example.com/products/widget-abc?sort=name"  # Matches the example regex
    target_url3 = "http://www.example.com/insecure"  # Invalid scheme
    target_url4 = "https://www.malicious.com/attack"  # Not in allowlist
    target_url5 = "https://www.example.com/products/widget-123?sort=price&extra=malicious" # Extra parameter
    target_url6 = "https://www.example.com/products/<script>alert('XSS')</script>?sort=price" # XSS attempt
    target_url7 = "https://www.example.com/products/very-long-product-name-with-many-characters-to-exceed-path-length-limit?sort=price" # Long path
    target_url8 = "https://www.example.com/products/widget-123?sort=invalid" # Invalid sort parameter
    target_url9 = "https://www.example.com/products/WIDGET-123?sort=price" # Uppercase product ID
    target_url10 = "https://www.example.com/products/widget-123?sort=price " # Trailing space in sort
    target_url11 = "https://www.example.com/products/widget-123?sort=price%20" # URL encoded space in sort
    target_url12 = "https://www.example.com/products/widget-123\u00a0?sort=price" # Non-breaking space in product ID
    target_url13 = "https://www.example.com/products/widget-123?sort=price" + ("A"*2100) # Long URL to test path length limit
    target_url14 = "https://www.example.com/products/widget-123?sort=price" # Valid URL

    redirect_url1 = get_safe_redirect_url(target_url1)
    redirect_url2 = get_safe_redirect_url(target_url2)
    redirect_url3 = get_safe_redirect_url(target_url3)
    redirect_url4 = get_safe_redirect_url(target_url4)
    redirect_url5 = get_safe_redirect_url(target_url5)
    redirect_url6 = get_safe_redirect_url(target_url6)
    redirect_url7 = get_safe_redirect_url(target_url7)
    redirect_url8 = get_safe_redirect_url(target_url8)
    redirect_url9 = get_safe_redirect_url(target_url9)
    redirect_url10 = get_safe_redirect_url(target_url10)
    redirect_url11 = get_safe_redirect_url(target_url11)
    redirect_url12 = get_safe_redirect_url(target_url12)
    redirect_url13 = get_safe_redirect_url(target_url13)
    redirect_url14 = get_safe_redirect_url(target_url14)

    print(f"Redirect URL 1: {redirect_url1}")
    print(f"Redirect URL 2: {redirect_url2}")
    print(f"Redirect URL 3: {redirect_url3}")
    print(f"Redirect URL 4: {redirect_url4}")
    print(f"Redirect URL 5: {redirect_url5}")
    print(f"Redirect URL 6: {redirect_url6}")
    print(f"Redirect URL 7: {redirect_url7}")
    print(f"Redirect URL 8: {redirect_url8}")
    print(f"Redirect URL 9: {redirect_url9}")
    print(f"Redirect URL 10: {redirect_url10}")
    print(f"Redirect URL 11: {redirect_url11}")
    print(f"Redirect URL 12: {redirect_url12}")
    print(f"Redirect URL 13: {redirect_url13}")
    print(f"Redirect URL 14: {redirect_url14}")

    # Example of using the redirect URL in a web framework (e.g., Flask)
    # from flask import Flask, redirect, request, escape
    # app = Flask(__name__)
    # @app.route('/redirect')
    # def my_redirect():
    #     target = request.args.get('target')
    #     redirect_url = get_safe_redirect_url(target)
    #     # IMPORTANT:  HTML-encode the redirect URL before passing it to redirect()
    #     # redirect_url = escape(redirect_url)  # Use escape() from markupsafe
    #     return redirect(redirect_url, code=302) # Use 302 for temporary redirect

