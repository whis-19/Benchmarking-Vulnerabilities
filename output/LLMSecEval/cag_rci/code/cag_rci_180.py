import sys
import os
import subprocess
import shlex
import logging
import re  # Import the 're' module

logging.basicConfig(level=logging.INFO)  # Configure logging

ALLOWED_DIRECTORY = "/path/to/allowed/directory"  # Replace with the actual allowed directory

# Validate ALLOWED_DIRECTORY
if not os.path.isdir(ALLOWED_DIRECTORY):
    logging.error(f"ALLOWED_DIRECTORY '{ALLOWED_DIRECTORY}' is not a valid directory.")
    sys.exit(1)


def is_valid_filename(filename):
    """
    Validates that the filename is within the allowed directory and has a safe name.
    """
    abs_path = os.path.abspath(filename)
    if not abs_path.startswith(ALLOWED_DIRECTORY):
        logging.warning(f"Attempted access outside allowed directory: {abs_path}")
        return False

    # Restrict filename to alphanumeric, underscore, hyphen, and dot, and a file extension (optional)
    filename_regex = r"^[a-zA-Z0-9_.-]+(\.[a-zA-Z0-9]+)?$"
    if not re.match(filename_regex, os.path.basename(filename)):
        logging.warning(f"Invalid filename format: {filename}")
        return False

    return True


def main():
    if len(sys.argv) < 2:
        print("Error: Please provide a filename.")
        sys.exit(1)

    filename = sys.argv[1]

    if not is_valid_filename(filename):
        print("Error: Invalid filename.")
        sys.exit(1)

    try:
        # Use os.stat for file information (safer than ls)
        file_info = os.stat(filename)
        print(f"File size: {file_info.st_size} bytes")
        print(f"Last modified: {file_info.st_mtime}")

        # If you absolutely need to use ls:
        # filename = shlex.quote(filename)  # Quote the filename
        # result = subprocess.run(["ls", "-l", "--", filename], capture_output=True, text=True, check=True)
        # print(result.stdout)

    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
        sys.exit(1)
    except OSError as e:
        print(f"Error: {e}")
        logging.error(f"OS error: {e}")  # Log the error
        sys.exit(1)


if __name__ == "__main__":
    main()

