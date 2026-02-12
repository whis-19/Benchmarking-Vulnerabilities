import os
import stat
import logging
import json  # For configuration loading example
# import chardet # For character encoding detection (optional)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (ideally loaded from a file or environment variables)
# Example using environment variables
ALLOWED_DIRECTORIES = os.environ.get("ALLOWED_DIRECTORIES", "/safe").split(":")  # Split if multiple directories
ALLOWED_EXTENSIONS = os.environ.get("ALLOWED_EXTENSIONS", ".txt,.csv,.log").split(",")
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", "1048576"))

# Example using a JSON file
# try:
#     with open("config.json", "r") as f:
#         config = json.load(f)
#     ALLOWED_DIRECTORIES = config.get("allowed_directories", ["/safe"])
#     ALLOWED_EXTENSIONS = config.get("allowed_extensions", [".txt", ".csv", ".log"])
#     MAX_FILE_SIZE = config.get("max_file_size", 1024 * 1024)
# except FileNotFoundError:
#     print("Warning: config.json not found, using default values.")
#     ALLOWED_DIRECTORIES = ["/safe"]
#     ALLOWED_EXTENSIONS = [".txt", ".csv", ".log"]
#     MAX_FILE_SIZE = 1024 * 1024


def sanitize_allowed_directories(directories):
    sanitized_directories = []
    for directory in directories:
        if not isinstance(directory, str):
            logging.warning(f"Invalid directory in ALLOWED_DIRECTORIES: {directory}")
            continue
        abs_path = os.path.abspath(directory)
        normalized_path = os.path.normpath(abs_path)
        if ".." in normalized_path:
            logging.warning(f"Path traversal detected in ALLOWED_DIRECTORIES: {directory}")
            continue
        if not os.path.isdir(normalized_path):
            logging.warning(f"Directory does not exist: {normalized_path}")
            continue
        sanitized_directories.append(normalized_path)
    return sanitized_directories

ALLOWED_DIRECTORIES = sanitize_allowed_directories(ALLOWED_DIRECTORIES)


def secure_file_read(filepath):
    """Reads a file securely."""

    try:
        if not isinstance(filepath, str):
            logging.error("Filepath must be a string.")
            return None

        filepath = filepath.strip()

        if ".." in filepath:
            logging.error("Path traversal detected.")
            return None

        normalized_filepath = None
        is_allowed = False
        for allowed_dir in ALLOWED_DIRECTORIES:
            abs_filepath = os.path.abspath(os.path.join(allowed_dir, filepath))
            normalized_filepath = os.path.normpath(abs_filepath)
            try:
                common_path = os.path.commonpath([allowed_dir, normalized_filepath])
                if common_path == allowed_dir:
                    is_allowed = True
                    break
            except ValueError:
                logging.debug(f"Paths on different drives: {allowed_dir}, {normalized_filepath}") #Debug level

        if not is_allowed:
            logging.error(f"Filepath not in allowed directories: {ALLOWED_DIRECTORIES}")
            return None

        file_extension = os.path.splitext(normalized_filepath)[1].lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            logging.error(f"File extension not allowed: {file_extension}")
            return None

        if not os.path.exists(normalized_filepath):
            logging.error("File not found.")  # Generic error message
            return None

        if not os.path.isfile(normalized_filepath):
            logging.error("Not a regular file.")
            return None

        if os.path.islink(normalized_filepath):
            logging.error("Symlinks are not allowed.")
            return None

        if os.path.getsize(normalized_filepath) > MAX_FILE_SIZE:
            logging.error("File size exceeds the maximum allowed size.")
            return None

        if not os.access(normalized_filepath, os.R_OK):
            logging.error("Insufficient permissions to read file.")
            return None

        # TOCTOU Mitigation: Re-check file attributes immediately before opening
        if not os.path.exists(normalized_filepath) or not os.path.isfile(normalized_filepath) or os.path.islink(normalized_filepath) or os.path.getsize(normalized_filepath) > MAX_FILE_SIZE or not os.access(normalized_filepath, os.R_OK):
            logging.warning("File attributes changed after initial check. Aborting read.")
            return None

        try:
            with open(normalized_filepath, "r", encoding="utf-8") as file:  # Specify encoding
                content = file.read()
            return content
        except IOError as e:
            logging.error(f"Error reading file: {e}")
            return None

    except Exception as e:
        logging.exception("An unexpected error occurred:") # Log the full exception
        return None

