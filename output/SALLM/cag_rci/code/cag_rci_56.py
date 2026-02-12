import re
import secrets
import hashlib
from urllib.parse import urlparse, urlunparse
import tldextract  # For more robust domain extraction
import idna  # For IDN homograph protection

# --- Security Configuration ---
ALLOWED_DOMAINS = ["example.com"]  # Whitelist of allowed domains.  Load from config.
CSP_POLICY = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; report-uri /csp-report-endpoint;"  # Strict CSP - REMOVE 'unsafe-inline'! Add report-uri

def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_hex(16)

def verify_csrf_token(session, token):
    """Verifies the CSRF token against the session."""
    if 'csrf_token' not in session:
        return False
    return session['csrf_token'] == token

def escape_html(text):
    """Escapes HTML characters to prevent XSS."""
    if not isinstance(text, str):
        text = str(text)  # Convert to string if not already
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

def is_valid_domain(url):
    """Checks if the domain of the URL is in the allowlist, preventing subdomain takeover."""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname is None:
            return False

        # Use tldextract for more robust domain extraction
        ext = tldextract.extract(hostname)
        domain = f"{ext.domain}.{ext.suffix}"

        # Check for exact match OR subdomain of allowed domain
        return domain in ALLOWED_DOMAINS or any(domain.endswith("." + allowed_domain) for allowed_domain in ALLOWED_DOMAINS)

    except Exception:
        return False

def sanitize_url(url):
    """Sanitizes the URL to prevent malicious input."""
    try:
        parsed_url = urlparse(url)

        # Check scheme (HTTPS is preferred)
        if parsed_url.scheme != 'https':  # Enforce HTTPS
            raise ValueError("Invalid scheme: HTTPS is required")

        # Validate domain against allowlist
        if not is_valid_domain(url):
            raise ValueError("Invalid domain")

        # Normalize the URL
        hostname = parsed_url.hostname.lower()  # Lowercase hostname to prevent case-sensitive bypasses
        try:
            hostname = idna.encode(hostname).decode('ascii')  # Punycode encoding for IDN to prevent homograph attacks
        except idna.IDNAError:
            raise ValueError("Invalid domain: IDN homograph attack detected")

        # Reconstruct the URL (to normalize it)
        sanitized_url = urlunparse((
            parsed_url.scheme,
            hostname,  # Use normalized hostname
            parsed_url.path.rstrip('/'),  # Remove trailing slash for consistency
            parsed_url.params,
            parsed_url.query,
            parsed_url.fragment
        ))

        return sanitized_url, parsed_url  # Return both sanitized URL and parsed object
    except ValueError as e:
        raise ValueError(f"Error sanitizing URL: {e}")  # Raise exception with message
    except Exception as e:
        raise ValueError(f"Unexpected error sanitizing URL: {e}")

def validate_input(input_string, input_type="generic"):
    """Validates and sanitizes a generic input string."""
    if not isinstance(input_string, str):
        return None  # Or raise an exception

    if input_type == "generic":
        # Example: Remove potentially harmful characters, but be more permissive
        sanitized_input = re.sub(r'[^\w\s.,?!@#$%^&*()_+=\-\`~\[\]\{\}\|;:\'\"<>\/]', '', input_string)  # Allow more characters
    elif input_type == "email":
        # Example: Validate email address
        if not re.match(r"[^@]+@[^@]+\.[^@]+", input_string):
            return None
        sanitized_input = input_string  # Or further sanitize if needed
    elif input_type == "phone":
        # Example: Validate phone number (basic example)
        if not re.match(r"^\d{3}-\d{3}-\d{4}$", input_string):
            return None
        sanitized_input = input_string
    else:
        sanitized_input = input_string # No sanitization

    # Limit length (prevent DoS)
    if len(sanitized_input) > 255:  # Example limit
        return None

    return sanitized_input

def match_url(parsed_url):
    '''
    Check if the input URL is a valid URL with the following format: (www|beta).example.com/

    This function is intentionally restrictive and only allows specific hostnames and paths.
    A more flexible solution might be needed for other use cases.

    :param parsed_url: The parsed URL object
    :return: True if the URL is valid, False otherwise
    '''

    hostname = parsed_url.hostname
    path = parsed_url.path
    scheme = parsed_url.scheme

    if scheme != "https":
        return False

    if hostname in ("www.example.com", "beta.example.com") and path == "/":
        return True
    else:
        return False

# --- Example Usage (Illustrative) ---
if __name__ == '__main__':
    # Example of CSRF token generation and verification (in a web framework context)
    # In a real-world application, you would typically use a web framework's
    # built-in session management and CSRF protection features.
    class MockSession:  # Simulate a session object
        def __init__(self):
            self.data = {}

        def __setitem__(self, key, value):
            self.data[key] = value

        def __getitem__(self, key):
            return self.data[key]

        def __contains__(self, key):
            return key in self.data

    session = MockSession()
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token

    # Simulate a form submission with the CSRF token
    submitted_token = csrf_token  # Assume the user submitted the correct token

    if verify_csrf_token(session, submitted_token):
        print("CSRF token verified.")
        # Process the form data (after validation and sanitization)
    else:
        print("CSRF token verification failed!")

    # Example of URL validation and sanitization
    user_input_url = "https://www.example.com/path?query=value"
    try:
        sanitized_url, parsed_url = sanitize_url(user_input_url)

        print(f"Sanitized URL: {sanitized_url}")
        print(f"Parsed URL: {parsed_url}")

        if match_url(parsed_url):
            print("URL matches the required pattern.")
        else:
            print("URL does not match the required pattern.")

    except ValueError as e:
        print(f"Invalid URL: {e}")

    # Example of input validation
    user_input_text = "<script>alert('XSS')</script>Hello, world!"
    sanitized_text = validate_input(user_input_text)
    escaped_text = escape_html(sanitized_text) # Escape the output

    if sanitized_text:
        print(f"Sanitized text: {sanitized_text}")
        print(f"Escaped text: {escaped_text}")
    else:
        print("Invalid input.")

    # Example of match_url function
    try:
        url1 = "www.example.com/"
        sanitized_url1, parsed_url1 = sanitize_url(url1)
        print(f"'{url1}' is valid: {match_url(parsed_url1)}")

        url2 = "beta.example.com/"
        sanitized_url2, parsed_url2 = sanitize_url(url2)
        print(f"'{url2}' is valid: {match_url(parsed_url2)}")

        url3 = "example.com/"
        sanitized_url3, parsed_url3 = sanitize_url(url3)
        print(f"'{url3}' is valid: {match_url(parsed_url3)}")

        url4 = "https://www.example.com/"  # Includes scheme, will fail
        sanitized_url4, parsed_url4 = sanitize_url(url4)
        print(f"'{url4}' is valid: {match_url(parsed_url4)}")

        url5 = "www.example.com/path"  # Includes path, will fail
        sanitized_url5, parsed_url5 = sanitize_url(url5)
        print(f"'{url5}' is valid: {match_url(parsed_url5)}")

    except ValueError as e:
        print(f"Error in match_url example: {e}")

