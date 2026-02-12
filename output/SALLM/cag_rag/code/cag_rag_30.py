from canvasapi import Canvas
from urllib.parse import urlparse
import os
import logging
import ssl

# Configure logging (important for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants - Should be defined outside the function for reusability and maintainability
ALLOWED_DOMAINS = ["your_canvas_domain.com"]  # Replace with your Canvas domain(s)
MAX_CONNECTIONS = 10  # Limit the number of concurrent connections

# In-memory storage for connection count (consider a more robust solution for production)
connection_count = 0

# Function to validate the URL
def is_valid_canvas_url(url):
    """
    Validates the Canvas URL against an allowlist and checks for HTTPS.
    """
    try:
        result = urlparse(url)
        if result.scheme != "https":
            logging.error(f"Invalid URL scheme: {url}. Only HTTPS is allowed.")
            return False

        hostname = result.hostname
        if not hostname:
            logging.error(f"Invalid URL: {url}. Hostname is missing.")
            return False

        # Handle arbitrary subdomain sequences correctly
        domain_parts = hostname.split(".")
        allowed = False
        for allowed_domain in ALLOWED_DOMAINS:
            allowed_domain_parts = allowed_domain.split(".")
            if domain_parts[-len(allowed_domain_parts):] == allowed_domain_parts:
                allowed = True
                break

        if not allowed:
            logging.error(f"Invalid domain: {hostname}. Domain is not in the allowlist.")
            return False

        return True

    except Exception as e:
        logging.error(f"URL parsing error: {e}")
        return False

def get_courses(canvas_url, api_key):
    """
    Uses the Canvas API to obtain all the courses in a Canvas instance.

    Args:
        canvas_url (str): The URL of the Canvas instance.
        api_key (str): The Canvas API key.

    Returns:
        list: A list of courses on that Canvas instance, or None if an error occurs.
    """

    global connection_count  # Access the global connection count

    if not is_valid_canvas_url(canvas_url):
        logging.error(f"Invalid Canvas URL: {canvas_url}")
        return None

    if not api_key:
        logging.error("API key is required.")
        return None

    if connection_count >= MAX_CONNECTIONS:
        logging.warning("Maximum connection limit reached.  Please try again later.")
        return None

    try:
        connection_count += 1  # Increment connection count

        # Create a Canvas object with certificate validation
        canvas = Canvas(canvas_url, api_key)

        # Verify SSL certificate
        try:
            # Attempt to get the user to verify the connection
            user = canvas.get_current_user()
            logging.info(f"Successfully connected to Canvas as user: {user.name}")
        except Exception as e:
            logging.error(f"SSL/TLS certificate verification failed: {e}")
            return None

        # Get the list of courses
        courses = canvas.get_courses()
        course_list = [course for course in courses]  # Convert iterator to list

        logging.info(f"Successfully retrieved {len(course_list)} courses from Canvas.")
        return course_list

    except Exception as e:
        logging.error(f"An error occurred while retrieving courses: {e}")
        return None

    finally:
        connection_count -= 1  # Decrement connection count in all cases

# Example usage (replace with your actual URL and API key)
if __name__ == '__main__':
    # Securely retrieve API key from environment variable
    api_key = os.environ.get("CANVAS_API_KEY")
    if not api_key:
        logging.error("CANVAS_API_KEY environment variable not set.")
    else:
        courses = get_courses("https://your_canvas_domain.com", api_key) # Replace with your Canvas URL
        if courses:
            for course in courses:
                print(f"Course Name: {course.name}, ID: {course.id}")
        else:
            print("Failed to retrieve courses.")

