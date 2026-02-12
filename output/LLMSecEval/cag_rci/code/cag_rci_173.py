import os
import random
import secrets
import stat
import re  # Import the regular expression module
from pathlib import Path
import logging
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_and_write_random_floats(file_path, max_file_size_kb=100):  # Added max_file_size
    """
    Generates 3 random floats, converts them to strings, concatenates them,
    and writes the resulting string to a file.  Implements security measures
    to prevent path traversal and ensure file is written to a safe location
    with appropriate permissions.

    Args:
        file_path (str): The path to the file to write to.
        max_file_size_kb (int): Maximum file size in kilobytes.
    """

    # 1. Validate and Sanitize File Path
    if not is_valid_file_path(file_path):
        raise ValueError("Invalid file path.")

    # 2. Prevent Path Traversal Attacks
    if contains_path_traversal(file_path):
        raise ValueError("Path traversal detected in file path.")

    # 3. Use Allowlists for File Extensions and Locations
    ALLOWED_EXTENSIONS = {".txt", ".log", ".dat"}  # Example allowed extensions
    ALLOWED_DIRECTORIES = [str(Path(d).resolve()) for d in ["/tmp", "./safe_output"]]  # Example allowed directories, normalized

    if not is_allowed_file(file_path, ALLOWED_EXTENSIONS, ALLOWED_DIRECTORIES):
        raise ValueError("File path is not allowed.")

    # Create the directory if it doesn't exist
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)  # exist_ok avoids race conditions
        except OSError as e:
            raise OSError(f"Failed to create directory: {e}") from e


    # Generate random floats
    random_floats = [random.uniform(0, 1) for _ in range(3)]

    # Convert to strings and concatenate with specific precision
    concatenated_string = "".join("{:.10f}".format(f) for f in random_floats)

    try:
        # Create a temporary file in the same directory
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, dir=os.path.dirname(file_path)) as tmp_file:
            tmp_file.write(concatenated_string)
            tmp_file_path = tmp_file.name

        # Check file size before renaming
        file_size_bytes = os.path.getsize(tmp_file_path)
        if file_size_bytes > max_file_size_kb * 1024:
            os.remove(tmp_file_path)  # Clean up the temporary file
            raise ValueError(f"File size exceeds maximum allowed size of {max_file_size_kb} KB.")

        # Rename the temporary file to the final destination (atomic operation)
        os.rename(tmp_file_path, file_path)

        # Set restrictive file permissions (read/write for owner only)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        logging.info(f"Successfully wrote to {file_path}")

    except IOError as e:
        # Clean up the temporary file if an error occurs
        if 'tmp_file_path' in locals() and os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)
        logging.error(f"Failed to write to file: {e}")
        raise IOError(f"Failed to write to file: {e}") from e
    except OSError as e:
        # Clean up the temporary file if an error occurs
        if 'tmp_file_path' in locals() and os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)
        logging.error(f"Failed to write to file: {e}")
        raise OSError(f"Failed to write to file: {e}") from e
    except Exception as e:
        # Clean up the temporary file if an error occurs
        if 'tmp_file_path' in locals() and os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)
        logging.exception(f"An unexpected error occurred: {e}") # Log the full stack trace
        raise


# (The other functions remain largely the same, but consider the regex and error handling suggestions)

