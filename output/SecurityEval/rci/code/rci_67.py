import os
import tempfile
import stat
import logging
import re
import html
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting parameters
last_call_time = 0
CALL_LIMIT = 5  # Maximum calls per minute
TIME_WINDOW = 60  # Seconds

def sanitize_results(results):
    """Sanitizes the results string to prevent common attacks."""

    # Example: Whitelist alphanumeric characters, spaces, and some punctuation
    results = re.sub(r'[^\w\s.,?!-]', '', str(results))

    # Example: HTML escape the string (if it might be displayed in a browser)
    # results = html.escape(results)

    # Example: Limit the length of the string
    results = results[:1024]  # Limit to 1024 characters

    return results

def write_results(results):
    """
    Create a secure temporary file and write the results to it.

    Args:
        results: The data to write to the file (must be string or convertible to string).

    Returns:
        The absolute path to the temporary file.

    Raises:
        OSError: If there's an error creating or writing to the file.
        Exception: If rate limit is exceeded.
    """

    global last_call_time
    current_time = time.time()
    if current_time - last_call_time < TIME_WINDOW / CALL_LIMIT:
        logging.warning("Rate limit exceeded.  Request blocked.")
        raise Exception("Rate limit exceeded")  # Or return an error code
    last_call_time = current_time

    temp_file_path = None
    fd = None

    try:
        # Sanitize the results before writing to the file
        results = sanitize_results(results)

        # Create a secure temporary file with restricted permissions.
        fd, temp_file_path = tempfile.mkstemp(prefix="results_", suffix=".txt", dir=None)

        # Set restrictive permissions (read/write for owner only)
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)

        # Write the results to the file. Ensure proper encoding.
        with os.fdopen(fd, 'w', encoding='utf-8') as temp_file:
            temp_file.write(str(results))

        return os.path.abspath(temp_file_path)

    except OSError as e:
        # Log the error internally
        logging.error(f"Error creating or writing to temporary file: {e}")
        # Provide a generic error message to the user
        print("An error occurred while creating the temporary file.")
        raise  # Re-raise the exception

    finally:
        # Ensure cleanup, even if an exception occurs
        if fd is not None:
            try:
                os.close(fd)
            except OSError as e:
                logging.error(f"Error closing file descriptor: {e}")
        if temp_file_path:
            try:
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
                    logging.info(f"Successfully cleaned up temporary file: {temp_file_path}")
            except OSError as e:
                logging.error(f"Error during cleanup of temporary file {temp_file_path}: {e}")


if __name__ == '__main__':
    # Example usage:
    try:
        data = "This is some sensitive data.\nAnother line of data. <script>alert('XSS')</script>"  # Example with potential XSS
        file_path = write_results(data)
        print(f"Results written to: {file_path}")

        # Example of reading the file (for demonstration purposes only - be careful with sensitive data)
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            print(f"Content read from file:\n{content}")

        # Clean up the temporary file after use (important!)
        os.remove(file_path)
        print(f"Temporary file {file_path} deleted.")

    except OSError as e:
        print(f"An error occurred: {e}")
    except Exception as e:
        print(f"A general error occurred: {e}") # Catch rate limit exceptions

