import os
import fcntl  # For O_NOFOLLOW
import logging
import unicodedata
import json  # For loading configuration (example)
import re  # For regular expression validation

# --- Configuration Loading (Example) ---
try:
    with open('config.json', 'r') as f:
        config = json.load(f)
        ALLOWED_DIRECTORIES = config.get("allowed_directories", ["/safe"])  # Absolute paths only
        ALLOWED_EXTENSIONS = config.get("allowed_extensions", [".txt", ".pdf", ".csv"])  # Lowercase with leading dot
        MAX_FILE_SIZE = config.get("max_file_size", 1024 * 1024)  # 1MB limit
except FileNotFoundError:
    # Use default values if config file is missing
    ALLOWED_DIRECTORIES = ["/safe"]
    ALLOWED_EXTENSIONS = [".txt", ".pdf", ".csv"]
    MAX_FILE_SIZE = 1024 * 1024
except json.JSONDecodeError:
    print("Error: Invalid JSON in config.json. Using default values.")
    ALLOWED_DIRECTORIES = ["/safe"]
    ALLOWED_EXTENSIONS = [".txt", ".pdf", ".csv"]
    MAX_FILE_SIZE = 1024 * 1024

# --- Logging Configuration ---
# Ideally, configure logging once at the application startup.
# See https://docs.python.org/3/library/logging.html for details.
# Example:
logging.basicConfig(filename='/var/log/myapp/file_access.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def secure_file_read(requested_file):
    """
    Reads a file from a safe directory after thorough validation.

    Args:
        requested_file (str): The name of the file to read (without path).

    Returns:
        str: The content of the file if successful, None otherwise.
    """

    try:
        # 1. Sanitize and Validate File Name
        if not isinstance(requested_file, str):
            logging.error("Invalid file name type.")
            print("Error: Invalid file name.")  # Generic user message
            return None

        # Basic sanitization: remove leading/trailing whitespace and normalize case
        filename = requested_file.strip().lower()

        # Normalize Unicode characters to prevent path traversal bypasses
        filename = unicodedata.normalize('NFKC', filename)

        if not filename:
            logging.error("Empty file name.")
            print("Error: Invalid file name.")  # Generic user message
            return None

        # --- Regular Expression Validation (Example) ---
        # Allow only alphanumeric characters, underscores, and periods
        filename_regex = r"^[a-z0-9_.]+$"
        if not re.match(filename_regex, filename):
            logging.warning(f"Invalid characters in filename: {filename}")
            print("Error: Invalid file name.") # Generic user message
            return None

        # Check for path traversal attempts (most important)
        if ".." in filename:
            logging.warning(f"Path traversal detected in filename: {filename}")
            print("Error: Invalid file name.")  # Generic user message
            return None

        # Check for absolute paths or attempts to escape the base directory
        if os.path.isabs(filename):
            logging.warning(f"Absolute path not allowed: {filename}")
            print("Error: Invalid file name.")  # Generic user message
            return None

        # 2. Construct the full file path
        filepath = None
        for allowed_dir in ALLOWED_DIRECTORIES:
            potential_filepath = os.path.normpath(os.path.join(allowed_dir, filename))

            # Check if the file is actually within the allowed directory
            if os.path.abspath(potential_filepath).startswith(os.path.abspath(allowed_dir)):
                filepath = potential_filepath
                break  # Found a valid path, no need to check other allowed directories

        if filepath is None:
            logging.error(f"File not found in allowed directories: {filename}")
            print("Error: File not found.")  # Generic user message
            return None

        # 3. Validate File Extension
        file_extension = os.path.splitext(filename)[1]
        if file_extension not in ALLOWED_EXTENSIONS:
            logging.warning(f"File extension '{file_extension}' not allowed for file: {filename}")
            print("Error: Invalid file type.")  # Generic user message
            return None

        # 4. Check File Existence and Permissions (Before Opening)
        if not os.path.exists(filepath):
            logging.error(f"File does not exist: {filepath}")
            print("Error: File not found.")  # Generic user message
            return None

        # --- Handle O_NOFOLLOW Availability ---
        if hasattr(fcntl, 'O_NOFOLLOW'):
            try:
                fd = os.open(filepath, os.O_RDONLY | fcntl.O_NOFOLLOW)  # Open with O_NOFOLLOW
                with open(fd, "r") as file:
                    content = file.read()
                os.close(fd)
                return content
            except OSError as e:
                logging.error(f"OSError reading file {filepath} (possible symlink issue): {e}", exc_info=True)
                print("Error: Could not read file.")  # Generic user message
                return None
        else:
            logging.warning("fcntl.O_NOFOLLOW not available.  TOCTOU vulnerability possible.")
            # Fallback: Rely on file existence and permissions checks (less secure)
            if not os.path.isfile(filepath):
                logging.error(f"File is not a regular file: {filepath}")
                print("Error: Could not read file.")  # Generic user message
                return None
            try:
                with open(filepath, "r") as file:
                    content = file.read()
                return content
            except OSError as e:
                logging.error(f"OSError reading file {filepath}: {e}", exc_info=True)
                print("Error: Could not read file.")  # Generic user message
                return None


        # Check file size to prevent DoS
        file_size = os.path.getsize(filepath)
        if file_size > MAX_FILE_SIZE:
            logging.warning(f"File too large: {filepath} (size: {file_size})")
            print("Error: File too large.")  # Generic user message
            return None

        # Check read permissions (using os.access)
        if not os.access(filepath, os.R_OK):
            logging.error(f"Insufficient permissions to read file: {filepath}")
            print("Error: Could not read file.")  # Generic user message
            return None

    except Exception as e:
        logging.exception(f"Unexpected error processing file {requested_file}: {e}")
        print("Error: An unexpected error occurred.")  # Generic user message
        return None

