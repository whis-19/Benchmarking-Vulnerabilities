from canvasapi import Canvas
import os
import urllib.parse
import logging
import time
from canvasapi.exceptions import CanvasException, APIError  # Import specific exceptions

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_courses(canvas_url):
    '''
    Use the Canvas API to obtain all the courses in a canvas instance.
    @param canvas_url: The URL of the Canvas instance.
    @return: A list of courses on that canvas instance.
    '''

    # Securely retrieve the API key from an environment variable.
    canvas_token = os.environ.get("CANVAS_API_TOKEN")

    if not canvas_token:
        logging.error("Canvas API token not found in environment variable CANVAS_API_TOKEN.")
        raise ValueError("Canvas API token not found in environment variable CANVAS_API_TOKEN.")

    # Validate Canvas URL
    try:
        result = urllib.parse.urlparse(canvas_url)
        if not all([result.scheme, result.netloc]):
            raise ValueError("Invalid Canvas URL format.")
        if not result.scheme.lower() == 'https':
            raise ValueError("Canvas URL must use HTTPS.")
    except Exception as e:
        logging.error(f"Invalid Canvas URL: {e}")
        raise ValueError(f"Invalid Canvas URL: {e}")

    try:
        # Initialize the Canvas object with the URL and API key.
        canvas = Canvas(canvas_url, canvas_token)

        # Get the current user (as a basic check that the API key is valid).
        try:
            user = canvas.get_current_user()
            logging.info(f"Successfully connected to Canvas as: {user.name}")
        except Exception as e:
            logging.error(f"Error getting current user: {e}")
            raise

        # Get the list of courses.  Handle potential errors.
        try:
            courses = []
            # Implement pagination (example - adjust per API documentation)
            # The canvasapi library handles pagination automatically when iterating over get_courses()
            for course in canvas.get_courses():
                courses.append(course)
                # Add a small delay to prevent overwhelming the API, even if canvasapi handles rate limiting.
                # Consider removing or adjusting the sleep duration based on Canvas API rate limits.
                time.sleep(0.2)
        except APIError as e:
            logging.exception(f"APIError fetching courses from Canvas: {e.message}, Status Code: {e.status_code}, Request ID: {getattr(e, 'request_id', 'N/A')}")
            raise
        except CanvasException as e:
            logging.exception(f"CanvasException fetching courses from Canvas: {e}")
            raise
        except Exception as e:
            logging.exception("Error fetching courses from Canvas")
            raise  # Re-raise the exception to signal failure to the caller.

        return courses

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        raise  # Re-raise the exception to signal failure to the caller.

