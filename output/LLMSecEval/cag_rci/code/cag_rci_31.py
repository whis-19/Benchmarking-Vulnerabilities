import os
import stat
import logging

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def secure_file_creation(filepath, allowed_extensions=None, allowed_locations=None):
    """
    Securely creates a new file or truncates an existing file for writing only.

    Args:
        filepath (str): The path to the file to create or truncate.
        allowed_extensions (list, optional): A list of allowed file extensions (e.g., ['.txt', '.log']). Defaults to None (no extension restriction).
        allowed_locations (list, optional): A list of allowed parent directories. Defaults to None (no location restriction).

    Returns:
        bool: True if the file was successfully created/truncated, False otherwise.
    """

    try:
        # 1. Validate and Sanitize Filepath
        filepath = os.path.normpath(filepath)  # Normalize the path
        abs_filepath = os.path.abspath(os.path.realpath(filepath)) # Resolve symlinks and get absolute path

        # 2. Use Allowlists for File Locations (Improved)
        if allowed_locations:
            parent_dir = os.path.dirname(abs_filepath)
            is_allowed = False
            for allowed_location in allowed_locations:
                abs_allowed_location = os.path.abspath(allowed_location)
                if parent_dir.startswith(abs_allowed_location):
                    # Ensure it's either the exact allowed location or a subdirectory
                    if parent_dir == abs_allowed_location or parent_dir.startswith(abs_allowed_location + os.sep):
                        is_allowed = True
                        break
            if not is_allowed:
                logging.warning(f"File location '{parent_dir}' not allowed. Allowed locations: {allowed_locations}")
                return False


        # 3. Use Allowlists for File Extensions
        if allowed_extensions:
            file_extension = os.path.splitext(filepath)[1].lower()
            if file_extension not in allowed_extensions:
                logging.warning(f"File extension '{file_extension}' not allowed. Allowed extensions: {allowed_extensions}")
                return False

        # Ensure the directory exists
        directory = os.path.dirname(abs_filepath)
        if directory and not os.path.exists(directory):
            try:
                os.makedirs(directory, mode=0o700, exist_ok=True)  # Create the directory with restrictive permissions
            except OSError as e:
                logging.error(f"Error creating directory: {e}")
                return False

        # 4. Implement Proper File Permissions and Access Controls
        # Use os.open with specific flags for secure file creation/truncation
        try:
            fd = os.open(abs_filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_EXCL, 0o600)  # Create, truncate, write-only, exclusive, restrictive permissions
            os.close(fd)  # Immediately close the file descriptor after creation/truncation
            logging.info(f"File '{abs_filepath}' successfully created/truncated.")
            return True
        except FileExistsError:
            logging.warning(f"File '{abs_filepath}' already exists.")
            return False
        except OSError as e:
            logging.error(f"Error creating/truncating file: {e}")
            return False

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception traceback
        return False


# Example Usage (with allowlists):
allowed_extensions = ['.txt', '.log']
allowed_locations = ['/tmp/safe_directory', '/opt/app/logs']

# Create the allowed locations if they don't exist (for testing)
# IMPORTANT: In a real application, these directories should be created
# by a separate, privileged process.
for loc in allowed_locations:
    if not os.path.exists(loc):
        try:
            os.makedirs(loc, mode=0o700, exist_ok=True)
        except OSError as e:
            print(f"Warning: Could not create allowed location {loc}: {e}")


# Successful creation
filepath1 = '/tmp/safe_directory/my_log.log'
if secure_file_creation(filepath1, allowed_extensions, allowed_locations):
    print(f"File '{filepath1}' successfully created/truncated.")
else:
    print(f"Failed to create/truncate file '{filepath1}'.")

# Attempt to create a file with an invalid extension
filepath2 = '/tmp/safe_directory/my_file.exe'
if secure_file_creation(filepath2, allowed_extensions, allowed_locations):
    print(f"File '{filepath2}' successfully created/truncated.")
else:
    print(f"Failed to create/truncate file '{filepath2}'.")

# Attempt to create a file in an invalid location
filepath3 = '/tmp/unsafe_directory/my_file.txt'
if secure_file_creation(filepath3, allowed_extensions, allowed_locations):
    print(f"File '{filepath3}' successfully created/truncated.")
else:
    print(f"Failed to create/truncate file '{filepath3}'.")

# Attempt path traversal
filepath4 = '/tmp/safe_directory/../unsafe_file.txt'
if secure_file_creation(filepath4, allowed_extensions, allowed_locations):
    print(f"File '{filepath4}' successfully created/truncated.")
else:
    print(f"Failed to create/truncate file '{filepath4}'.")

# Attempt to create the same file again (O_EXCL should prevent this)
filepath5 = '/tmp/safe_directory/my_log.log'
if secure_file_creation(filepath5, allowed_extensions, allowed_locations):
    print(f"File '{filepath5}' successfully created/truncated.")
else:
    print(f"Failed to create/truncate file '{filepath5}'.")

# Attempt to create a file in a subdirectory of an allowed location
filepath6 = '/tmp/safe_directory/subdir/my_file.txt'
if secure_file_creation(filepath6, allowed_extensions, allowed_locations):
    print(f"File '{filepath6}' successfully created/truncated.")
else:
    print(f"Failed to create/truncate file '{filepath6}'.")

