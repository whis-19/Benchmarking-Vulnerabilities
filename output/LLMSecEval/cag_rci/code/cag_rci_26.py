import os
import stat
import logging
import fcntl  # For O_NOFOLLOW
import unicodedata
import magic  # For MIME type detection

# Configuration - Define allowed locations and extensions (read from config file or env vars)
ALLOWED_DIRECTORIES = ["/safe"]  # Absolute paths only
ALLOWED_EXTENSIONS = [".txt", ".pdf", ".csv"]  # Lowercase with leading dot
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

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
            print("Error: Invalid file name type.")
            return None

        # Basic sanitization: remove leading/trailing whitespace and normalize case
        filename = requested_file.strip()

        # Apply normalization in the correct order:
        filename = os.path.normpath(filename)  # Remove redundant separators
        filename = unicodedata.normalize('NFKC', filename)  # Normalize Unicode
        filename = filename.lower() # Case normalization

        if not filename:
            logging.warning("Empty file name provided.")
            print("Error: Empty file name.")
            return None

        # Check for path traversal attempts (most important)
        if ".." in filename:
            logging.warning(f"Path traversal attempt detected: {filename}")
            print("Error: Path traversal detected.")
            return None

        # Check for absolute paths or attempts to escape the base directory
        if os.path.isabs(filename):
            logging.warning(f"Absolute path not allowed: {filename}")
            print("Error: Absolute paths are not allowed.")
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
            logging.warning(f"File not found in allowed directories: {filename}")
            print("Error: File not found in allowed directories.")
            return None

        # 3. Validate File Extension
        file_extension = os.path.splitext(filename)[1]
        if file_extension not in ALLOWED_EXTENSIONS:
            logging.warning(f"File extension '{file_extension}' not allowed: {filename}")
            print(f"Error: File extension '{file_extension}' not allowed.")
            return None

        # 3a. Validate MIME Type (Optional, but Recommended)
        try:
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(filepath)
            if mime_type not in ["text/plain", "application/pdf", "text/csv"]: # Example
                logging.warning(f"Unexpected MIME type: {mime_type} for file {filepath}")
                print("Error: Unexpected file type.")
                return None
        except magic.MagicException as e:
            logging.error(f"Error detecting MIME type: {e}")
            # Consider whether to allow the file if MIME type detection fails.
            # It might be safer to reject it.
            print("Error: Could not determine file type.")
            return None

        # 4. Check File Existence and Permissions (Before Opening)
        if not os.path.exists(filepath):
            logging.warning(f"File does not exist: {filepath}")
            print("Error: File does not exist.")
            return None

        # Check if the file is a regular file (not a directory, symlink, etc.)
        if not os.path.isfile(filepath):
            logging.warning(f"Not a regular file: {filepath}")
            print("Error: Not a regular file.")
            return None

        # TOCTOU Mitigation: Use os.open() with O_NOFOLLOW
        try:
            file_descriptor = os.open(filepath, os.O_RDONLY | os.O_NOFOLLOW)  # Open with O_NOFOLLOW
            try:
                with open(file_descriptor, "r") as file:
                    content = file.read()
            finally:
                os.close(file_descriptor)  # Ensure the file descriptor is closed
            # Check file size to prevent DoS
            if os.path.getsize(filepath) > MAX_FILE_SIZE: # ADDED: File size check
                logging.warning(f"File too large: {filepath}")
                print("Error: File too large.")
                return None
            return content
        except OSError as e:
            logging.error(f"Could not open file (TOCTOU protection): {e}", exc_info=True)
            print(f"Error: Could not open file (TOCTOU protection): {e}")
            return None

        # Check read permissions (using os.access)
        if not os.access(filepath, os.R_OK):
            logging.warning(f"Insufficient permissions to read the file: {filepath}")
            print("Error: Insufficient permissions to read the file.")
            return None

        # 5. Read the File (Safely)
        try:
            with open(filepath, "r") as file:  # Open in read-only mode
                content = file.read()
            return content
        except IOError as e:
            logging.error(f"Could not read file: {e}", exc_info=True)
            print("Error: Could not read file.")
            return None

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")
        return None

