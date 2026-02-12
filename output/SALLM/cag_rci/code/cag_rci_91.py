import urllib.request
import urllib.error
import logging
import idna
from urllib.parse import urlparse
import os
import socket
from lxml import etree

ALLOWED_XSLT_DOMAINS = ["example.com", "safe.example.org"]
MAX_XSLT_SIZE = 102400  # Example size limit

def fetch_and_parse_xslt(xslt_url):
    """Fetches and parses an XSLT stylesheet from a URL, with security checks."""

    if not is_safe_url(xslt_url):
        logging.warning(f"Unsafe XSLT URL: {xslt_url}")
        return "Error: Unsafe XSLT URL.", 400

    try:
        with urllib.request.urlopen(xslt_url, timeout=10) as response:  # Add timeout
            if response.status != 200:
                logging.error(f"Could not fetch XSLT from URL: HTTP status code {response.status} for URL: {xslt_url}")
                return f"Error: Could not fetch XSLT from URL: HTTP status code {response.status}", 400
            xslt_data = response.read()
            if len(xslt_data) > MAX_XSLT_SIZE:
                logging.warning(f"XSLT data exceeds maximum size ({MAX_XSLT_SIZE} bytes) for URL: {xslt_url}")
                return "Error: XSLT data too large.", 400
    except urllib.error.URLError as e:
        logging.error(f"Could not fetch XSLT from URL: {e} for URL: {xslt_url}")
        return f"Error: Could not fetch XSLT from URL: {e}", 400
    except socket.timeout:
        logging.error(f"Timeout fetching XSLT from URL: {xslt_url}")
        return "Error: Timeout fetching XSLT.", 400

    try:
        xslt_tree = etree.XML(xslt_data)  # Parse from the fetched data
        # WARNING: Even with size limits, complex XSLT stylesheets can be computationally expensive and lead to DoS attacks.
    except etree.XMLSyntaxError as e:
        logging.warning(f"Invalid XSLT syntax: {e} for URL: {xslt_url}")
        return f"Error: Invalid XSLT syntax: {e}", 400

    return xslt_tree, 200  # Return the parsed XSLT tree

def is_safe_url(url):
    """Checks if a URL is safe to fetch XSLT from."""
    try:
        result = urlparse(url)

        # Check scheme
        if result.scheme != 'https':
            logging.debug(f"Unsafe URL: Scheme is not HTTPS: {url}")
            return False

        hostname = result.hostname
        if not hostname:
            logging.debug(f"Unsafe URL: No hostname found in {url}")
            return False

        # Canonicalize the hostname
        try:
            hostname = idna.encode(hostname).decode('ascii')  # Convert to punycode and back to ASCII
        except idna.IDNAError as e:
            logging.debug(f"Unsafe URL: Invalid hostname (IDNA error): {e}")
            return False

        # Normalize hostname (lowercase, remove trailing dot, whitespace)
        hostname = hostname.lower().rstrip('.')
        hostname = hostname.strip()

        # Check if the hostname is in the allowlist (case-insensitive)
        if hostname not in [domain.lower() for domain in ALLOWED_XSLT_DOMAINS]:
            logging.debug(f"Unsafe URL: Hostname {hostname} not in allowlist: {hostname}")
            return False

        # Check path (restrict to specific paths if possible)
        # Example: Only allow URLs under /xslt/
        normalized_path = os.path.normpath(result.path) # Normalize the path
        if not normalized_path.startswith('/xslt/'):
            logging.debug(f"Unsafe URL: Path not allowed: {result.path}")
            return False

        # Check query parameters (sanitize or reject)
        # Example: Reject URLs with query parameters
        if result.query:
            logging.debug(f"Unsafe URL: Query parameters not allowed: {result.query}")
            return False

        # Check fragments (reject)
        if result.fragment:
            logging.debug(f"Unsafe URL: Fragments not allowed: {result.fragment}")
            return False

        return True

    except Exception as e:
        logging.error(f"Error parsing URL: {url} - {e}")
        return False

