from urllib.parse import urlparse, urljoin
import validators
import re

def is_safe_url(target):
    """
    Security: Validate that the redirect target is safe.
    Severity: High
    Risk: Open Redirect
    """
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))  # Resolve relative URLs.  This prevents attackers from using relative paths to bypass the prefix check.  For example, if allowed_paths contains '/index', an attacker could use '../example.com' to bypass the check without urljoin.
        # Check if the netloc matches the current host
        if ref_url.netloc != test_url.netloc:
            return False

        # Whitelist URL prefixes (exact matches only)
        allowed_paths = [urlparse(url_for('index')).path, urlparse(url_for('login')).path, urlparse(url_for('register')).path]  # Add more as needed
        return test_url.path in allowed_paths

    except ValueError:
        # Handle parsing errors (e.g., invalid URLs)
        return False

def validate_url(url):
    """
    Security: Validate and sanitize URLs.  More robust validation.
    Severity: Medium
    Risk: Potential for malicious code injection, SSRF
    """
    try:
        if not validators.url(url):
            return False

        result = urlparse(url)

        # Scheme Whitelisting
        allowed_schemes = ['http', 'https']
        if result.scheme not in allowed_schemes:
            return False

        # Basic SSRF protection (block access to localhost)
        if result.hostname in ('localhost', '127.0.0.1'):
            return False

        # Additional checks (length, disallowed characters, etc.)
        if len(url) > 2048:  # Limit URL length
            return False

        # More robust netloc validation (example: allow only alphanumeric and dots)
        # if not re.match(r"^[a-zA-Z0-9.]+$", result.netloc):
        #     return False
        # Security Note: Be careful with complex regular expressions as they can be vulnerable to ReDoS attacks.

        return True
    except ValueError as e:  # Catch specific exceptions and log them
        app.logger.error(f"URL validation error: {e}")  # Replace app.logger with your actual logger
        return False
    except TypeError as e:
        app.logger.error(f"URL validation error: {e}")
        return False
    except Exception as e: # Catch any other exception and log it
        app.logger.error(f"URL validation error: {e}")
        return False

