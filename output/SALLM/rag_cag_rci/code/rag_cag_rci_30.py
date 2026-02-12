from canvasapi import Canvas
from urllib.parse import urlparse
import os
import logging

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Configuration ---
ALLOWED_CANVAS_DOMAINS = ["your_institution.instructure.com"]  # Replace with your institution's domain
MAX_CONNECTIONS = 10  # Limit the number of concurrent connections

# --- Rate Limiting (Example - Adapt to your needs) ---
REQUEST_LIMIT = 100  # Maximum requests per minute
REQUEST_WINDOW = 60  # Time window in seconds
user_request_counts = {}  # Store request counts per user (e.g., based on IP or session ID)

# --- Authentication ---
API_KEY = os.environ.get("CANVAS_API_KEY")  # Store API key securely (e.g., environment variable)
if not API_KEY:
    logging.error("CANVAS_API_KEY environment variable not set.  Authentication will fail.")
    # Consider raising an exception here to prevent the program from running without the API key.

def is_valid_canvas_url(url):
    """
    Validates the Canvas URL against an allowlist of domains.
    Handles arbitrary subdomain sequences correctly.
    """
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            logging.warning(f"URL {url} is not using HTTPS.  Rejecting.")
            return False

        hostname = parsed_url.hostname
        if not hostname:
            logging.warning(f"URL {url} has no hostname. Rejecting.")
            return False

        # Check if the hostname ends with any of the allowed domains
        for allowed_domain in ALLOWED_CANVAS_DOMAINS:
            if hostname.endswith(allowed_domain):
                return True

        logging.warning(f"URL {url} is not in the allowlist. Rejecting.")
        return False

    except Exception as e:
        logging.error(f"Error parsing URL {url}: {e}")
        return False

def check_rate_limit(user_id):
    """
    Checks if a user has exceeded their request limit.
    """
    global user_request_counts
    import time

    now = time.time()
    if user_id not in user_request_counts:
        user_request_counts[user_id] = []

    # Remove requests older than the time window
    user_request_counts[user_id] = [ts for ts in user_request_counts[user_id] if now - ts < REQUEST_WINDOW]

    if len(user_request_counts[user_id]) >= REQUEST_LIMIT:
        logging.warning(f"User {user_id} has exceeded the request limit.")
        return False  # Rate limit exceeded

    user_request_counts[user_id].append(now)
    return True  # Rate limit not exceeded


def get_courses(canvas_url, user_id="default_user"):  # Added user_id for rate limiting
    """
    Use the Canvas API to obtain all the courses in a Canvas instance.

    @param canvas_url: The URL of the Canvas instance.
    @param user_id:  A unique identifier for the user making the request (for rate limiting).

    @return: A list of courses on that Canvas instance, or None if an error occurs.
    """

    if not is_valid_canvas_url(canvas_url):
        logging.error(f"Invalid Canvas URL: {canvas_url}")
        return None

    if not API_KEY:
        logging.error("API key is not set. Cannot connect to Canvas.")
        return None

    if not check_rate_limit(user_id):
        logging.warning(f"Rate limit exceeded for user {user_id}.  Cannot retrieve courses.")
        return None

    try:
        canvas = Canvas(canvas_url, API_KEY)
        courses = list(canvas.get_courses())  # Convert to list to ensure all courses are fetched
        logging.info(f"Successfully retrieved {len(courses)} courses from {canvas_url}")
        return courses

    except Exception as e:
        logging.error(f"An error occurred while retrieving courses from {canvas_url}: {e}")
        return None


if __name__ == '__main__':
    # Example Usage (replace with your actual Canvas URL)
    canvas_url = "https://your_institution.instructure.com"  # Replace with your Canvas URL
    courses = get_courses(canvas_url)

    if courses:
        print("Courses:")
        for course in courses:
            print(f"- {course.name} (ID: {course.id})")
    else:
        print("Failed to retrieve courses.")

