import os
import logging
import re
import html  # For HTML escaping
from canvasapi import Canvas
import urllib.parse
import requests
import ssl
import certifi
import sys  # For graceful exit
import time  # For rate limiting
from requests.exceptions import RequestException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration - Load from environment variables
ALLOWED_DOMAINS_CSV = os.environ.get("ALLOWED_DOMAINS_CSV")
ALLOWED_DOMAINS = ALLOWED_DOMAINS_CSV.split(",") if ALLOWED_DOMAINS_CSV else []
API_URL = os.environ.get("CANVAS_API_URL")  # Get from environment variable
API_KEY = os.environ.get("CANVAS_API_KEY")  # Get from environment variable

if not API_URL or not API_KEY:
    logging.critical("CANVAS_API_URL or CANVAS_API_KEY environment variables not set.")
    sys.exit(1)  # Exit gracefully

def is_valid_domain(url):
    """
    Checks if the domain of the URL is in the allowlist.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        # Regular expression for a valid domain name
        domain_regex = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
        if hostname:
            hostname = hostname.lower().strip()
            allowed_domains_normalized = [domain.lower().strip() for domain in ALLOWED_DOMAINS]
            if re.match(domain_regex, hostname) and hostname in allowed_domains_normalized:
                return True
            else:
                logging.warning(f"Invalid domain: {hostname}")
                return False
        else:
            logging.warning("No hostname found in URL.")
            return False
    except Exception as e:
        logging.error(f"Error parsing URL: {e}")
        return False

def validate_api_key(api_key):
    """Validates the API key format."""
    if not api_key:
        return False
    if len(api_key) < 32:  # Example minimum length
        return False
    if not api_key.isalnum(): # Example: Check if it's alphanumeric
        return False
    # Example: Check for a UUID-like format (replace with actual Canvas API key format)
    # if not re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", api_key):
    #     return False
    return True


def sanitize_url(url, context="url"):
    """
    Sanitizes the URL based on the context in which it will be used.
    For URL encoding, urllib.parse.quote is generally preferred over quote_plus
    because it encodes spaces as %20 instead of +.  Choose the appropriate
    encoding based on the context.
    """
    if context == "url":
        # URL encoding for use in requests
        sanitized_url = urllib.parse.quote(url, safe=":/")  # Use quote instead of quote_plus
    elif context == "html":
        # HTML escaping for display in HTML
        sanitized_url = html.escape(url)
    else:
        raise ValueError(f"Invalid sanitization context: {context}")
    return sanitized_url


def validate_ssl_certificate(url):
    """
    Validates the SSL/TLS certificate of the given URL.
    """
    try:
        # Use certifi to get the trusted CA certificates
        context = ssl.create_default_context(cafile=certifi.where())

        with requests.head(url, verify=context) as response:  # Use requests.head
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            # Log certificate details (optional)
            cert = response.raw.connection.sock.getpeercert()
            # Consider logging a hash instead of the full subject/issuer
            logging.info(f"SSL Certificate Subject: {cert.get('subject')}")
            logging.info(f"SSL Certificate Issuer: {cert.get('issuer')}")

        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"SSL/TLS certificate validation failed: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during SSL/TLS validation: {e}")
        return False


class CanvasAPIError(Exception):
    pass


def get_courses(canvas_url):
    '''
    Use the Canvas API to obtain all the courses in a canvas instance.
    @param canvas_url: The URL of the Canvas instance.
    @return: A list of courses on that canvas instance.
    '''

    # 1. Validate and Sanitize URL
    if not canvas_url:
        raise ValueError("Canvas URL cannot be empty.")

    if not is_valid_domain(canvas_url):
        raise ValueError(f"Canvas URL domain is not allowed. Allowed domains: {ALLOWED_DOMAINS}")

    # Validate API URL
    try:
        urllib.parse.urlparse(canvas_url)
    except:
        raise ValueError("Invalid Canvas URL format.")

    if not validate_api_key(API_KEY):
        logging.error("Invalid API Key format.")
        raise ValueError("Invalid API Key format.")

    sanitized_url = sanitize_url(canvas_url)

    # 3. Use HTTPS (Enforced by the canvasapi library and the requests library)
    parsed_url = urllib.parse.urlparse(sanitized_url)
    if parsed_url.scheme != "https":
        raise ValueError("Canvas URL must use HTTPS.")

    # 4. Validate SSL/TLS Certificates
    if not validate_ssl_certificate(sanitized_url):
        raise ValueError("SSL/TLS certificate validation failed for the Canvas URL.")

    try:
        # Initialize Canvas object
        canvas = Canvas(sanitized_url, API_KEY)  # Use the API_KEY from configuration

        # Get the current user
        user = canvas.get_current_user()
        logging.info(f"Successfully connected to Canvas as user: {user.name}") # Basic check

        # Get all courses
        courses = canvas.get_courses()
        course_list = list(courses)  # Convert the iterator to a list

        return course_list

    except RequestException as e:  # Catch requests-related exceptions (including rate limiting)
        logging.exception(f"An error occurred while fetching courses: {e}")
        # Implement retry logic with exponential backoff
        retry_after = int(e.response.headers.get('Retry-After', 60))  # Default retry after 60 seconds
        logging.warning(f"Rate limit hit. Retrying after {retry_after} seconds.")
        time.sleep(retry_after)
        # Recursively call get_courses to retry (with a maximum number of retries)
        # You'll need to add a retry counter to prevent infinite loops.
        raise CanvasAPIError(f"Failed to fetch courses after rate limit: {e}") from e

    except Exception as e:
        logging.exception(f"An error occurred while fetching courses: {e}") # Log the full traceback
        raise CanvasAPIError(f"Failed to fetch courses: {e}") from e # Raise a custom exception


if __name__ == '__main__':
    # Example Usage (Replace with your actual Canvas URL)
    try:
        courses = get_courses(API_URL) # Use the API_URL from configuration
        if courses:
            print("Courses found:")
            for course in courses:
                print(f"- {course.name} (ID: {course.id})")
        else:
            print("No courses found or an error occurred.")
    except ValueError as e:
        print(f"Error: {e}")
    except CanvasAPIError as e:
        print(f"Canvas API Error: {e}")

