from canvasapi import Canvas
import urllib.parse
import os
from dotenv import load_dotenv
import hashlib
import secrets
import logging
import threading
from ratelimit import limits, RateLimitException
import time

# Load environment variables (API_URL, API_KEY)
load_dotenv()
API_URL = os.getenv("CANVAS_API_URL")
API_KEY = os.getenv("CANVAS_API_KEY")  # Store API key securely (e.g., environment variable)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting configuration (e.g., 5 requests per second)
CALLS = 5
PERIOD = 1

# Connection limiting
MAX_CONNECTIONS = 10  # Example: Limit to 10 concurrent connections
connection_count = 0
connection_lock = threading.Lock()

# Known acceptable Canvas URLs (for validation)
ALLOWED_CANVAS_URLS = [
    "https://canvas.instructure.com",  # Example: Production Canvas
    "https://canvas.test.instructure.com",  # Example: Test Canvas
    # Add other allowed URLs here
]

# Secure password hashing function
def hash_password(password: str) -> str:
    """Hashes a password using a strong hashing algorithm (SHA-256)."""
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return f"{salt}:{hashed_password}"

# Verify password against stored hash
def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a password against a stored hash."""
    try:
        salt, hashed_password = stored_hash.split(":")
        salted_password = salt + password
        new_hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
        return new_hashed_password == hashed_password
    except ValueError:
        logging.error("Invalid stored hash format.")
        return False

# URL validation function
def is_valid_canvas_url(url: str) -> bool:
    """Validates a Canvas URL against a list of allowed URLs."""
    try:
        parsed_url = urllib.parse.urlparse(url)
        # Handle arbitrary subdomain sequences
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc.split('.')[-2]}.{parsed_url.netloc.split('.')[-1]}"
        return base_url in ALLOWED_CANVAS_URLS
    except Exception as e:
        logging.error(f"Error parsing URL: {e}")
        return False

# Rate limiting decorator
@limits(calls=CALLS, period=PERIOD)
def call_canvas_api(canvas, endpoint):
    """Rate-limited function to call the Canvas API."""
    try:
        return canvas.get(endpoint)  # Example: Replace with actual API call
    except Exception as e:
        logging.error(f"Error calling Canvas API: {e}")
        raise

def acquire_connection():
    """Acquires a connection, respecting the connection limit."""
    global connection_count
    with connection_lock:
        if connection_count >= MAX_CONNECTIONS:
            return False  # Connection limit reached
        connection_count += 1
        return True

def release_connection():
    """Releases a connection."""
    global connection_count
    with connection_lock:
        connection_count -= 1

def get_courses(canvas_url: str) -> list:
    """
    Use the Canvas API to obtain all the courses in a Canvas instance.

    Args:
        canvas_url: The URL of the Canvas instance.

    Returns:
        A list of courses on that Canvas instance, or an empty list if an error occurs.
    """

    if not is_valid_canvas_url(canvas_url):
        logging.warning(f"Invalid Canvas URL: {canvas_url}")
        return []

    try:
        # Initialize Canvas object
        canvas = Canvas(canvas_url, API_KEY)

        # Get the current user (as a basic authentication test)
        user = canvas.get_current_user()
        logging.info(f"Successfully authenticated as user: {user.name}")

        # Acquire a connection
        if not acquire_connection():
            logging.warning("Connection limit reached.  Unable to retrieve courses.")
            return []

        # Get courses (using rate limiting)
        try:
            courses = canvas.get_courses()
            course_list = [course for course in courses]  # Convert to a list
            logging.info(f"Successfully retrieved {len(course_list)} courses.")
            return course_list
        except RateLimitException as e:
            logging.warning(f"Rate limit exceeded: {e}")
            return []
        except Exception as e:
            logging.error(f"An error occurred while retrieving courses: {e}")
            return []
        finally:
            release_connection()  # Release the connection
    except Exception as e:
        logging.error(f"An error occurred during Canvas API interaction: {e}")
        return []

if __name__ == '__main__':
    # Example usage (replace with your actual Canvas URL)
    # Ensure CANVAS_API_URL and CANVAS_API_KEY are set in your environment
    if API_URL and API_KEY:
        courses = get_courses(API_URL)
        if courses:
            print("Courses:")
            for course in courses:
                print(f"- {course.name} (ID: {course.id})")
        else:
            print("Failed to retrieve courses.")
    else:
        print("Please set the CANVAS_API_URL and CANVAS_API_KEY environment variables.")

    # Example of password hashing and verification
    password = "my_secret_password"
    hashed_password = hash_password(password)
    print(f"Hashed password: {hashed_password}")

    is_correct = verify_password(password, hashed_password)
    print(f"Password verification: {is_correct}")

    is_correct_wrong_password = verify_password("wrong_password", hashed_password)
    print(f"Password verification with wrong password: {is_correct_wrong_password}")

