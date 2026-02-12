import tempfile
import os
import logging
import re  # Import the regular expression module

# Configure logging (optional, but recommended for security-related events)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_FOLDER = "/tmp/safe_results"  # Define a safe directory
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

def write_results(results, user_filename_part=""):  # Added user_filename_part
    '''
        Create a temporary file with UTF-8 encoding in a safe directory,
        write the unicode string results to it,
        and return its path.
    '''
    if not os.path.exists(SAFE_FOLDER):
        try:
            os.makedirs(SAFE_FOLDER, exist_ok=True)  # Create the directory if it doesn't exist
            os.chmod(SAFE_FOLDER, 0o700)  # Set restrictive permissions
        except OSError as e:
            logging.error(f"Failed to create safe directory: {e}")
            return None

    # Sanitize user input (VERY IMPORTANT!)
    sanitized_user_filename_part = re.sub(r'[^a-zA-Z0-9_.-]', '', user_filename_part)  # Allow only alphanumeric, underscore, period, and hyphen
    sanitized_user_filename_part = sanitized_user_filename_part[:32]  # Limit length
    if ".." in sanitized_user_filename_part or "/" in sanitized_user_filename_part or "\\" in sanitized_user_filename_part:
        logging.error("Invalid characters in user-provided filename part.")
        return None

    try:
        # Construct the filename
        filename = f"results_{sanitized_user_filename_part}.txt"
        filepath = os.path.join(SAFE_FOLDER, filename)

        # Create the file
        with open(filepath, 'w', encoding='utf-8') as f:
            # Check file size before writing
            if len(results.encode('utf-8')) > MAX_FILE_SIZE:
                logging.error("Result data exceeds maximum allowed file size.")
                f.close()
                os.remove(filepath)
                return None

            f.write(results)
            f.flush()  # Ensure data is written to disk

            # Verify the file is within the safe directory (extra security check)
            if not os.path.abspath(filepath).startswith(os.path.abspath(SAFE_FOLDER)):
                logging.error("File path is outside the safe directory.  Aborting.")
                f.close()
                os.remove(filepath)
                return None

            logging.info(f"Results written to: {filepath}")
            return filepath

    except OSError as e:
        logging.error(f"Error writing to file: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

