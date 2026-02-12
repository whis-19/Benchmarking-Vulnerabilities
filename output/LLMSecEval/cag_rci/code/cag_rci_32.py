import os
import stat
import logging  # Import the logging module

# Configure logging (adjust level and format as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def secure_write_config(file_path, important_config, allowed_extensions=None, allowed_locations=None):
    """
    Securely writes configuration data to a file.

    Args:
        file_path (str): The path to the file.
        important_config (str): The configuration data to write.
        allowed_extensions (list, optional): A list of allowed file extensions (e.g., ['.conf', '.txt']). Defaults to None.
        allowed_locations (list, optional): A list of allowed directory paths. Defaults to None.

    Returns:
        bool: True if the write was successful, False otherwise.
    """

    try:
        # 1. Validate and Sanitize File Path
        if not isinstance(file_path, str):
            logging.error("File path must be a string.")
            print("Error: Invalid file path.")  # Generic error for the user
            return False

        file_path = os.path.normpath(file_path)  # Normalize the path

        # 2. Prevent Path Traversal Attacks
        #if ".." in file_path: # Redundant check
        #    logging.error("Path traversal detected in file path.")
        #    print("Error: Invalid file path.")  # Generic error for the user
        #    return False

        abs_file_path = os.path.abspath(file_path)  # Get absolute path
        logging.debug(f"Normalized and absolute file path: {abs_file_path}") # Log the path

        # 3. Use Allowlists for File Extensions and Locations
        if allowed_extensions:
            file_extension = os.path.splitext(abs_file_path)[1].lower()
            if file_extension not in allowed_extensions:
                logging.error(f"File extension '{file_extension}' not allowed. Allowed extensions: {allowed_extensions}")
                print("Error: Invalid file extension.")  # Generic error for the user
                return False

        if allowed_locations:
            file_dir = os.path.dirname(abs_file_path)
            is_allowed = False
            for allowed_location in allowed_locations:
                if os.path.abspath(allowed_location) == file_dir:
                    is_allowed = True
                    break
            if not is_allowed:
                logging.error(f"File location '{file_dir}' not allowed. Allowed locations: {allowed_locations}")
                print("Error: Invalid file location.")  # Generic error for the user
                return False

            # Additional check to prevent writing to subdirectories of allowed locations
            if not any(os.path.abspath(allowed_location) == abs_file_path for allowed_location in allowed_locations):
                logging.warning(f"Writing to a subdirectory of an allowed location: {abs_file_path}")
                # Decide whether to allow this or not based on your security policy
                # If you want to prevent it, uncomment the following lines:
                print("Error: Writing to subdirectories is not allowed.")
                return False


        # Ensure the directory exists
        os.makedirs(os.path.dirname(abs_file_path), exist_ok=True)

        # 4. Implement Proper File Permissions and Access Controls
        # Open the file with specific permissions (e.g., read/write for owner only)
        # Using os.open for more control over permissions
        logging.info(f"Attempting to write to file: {abs_file_path}") # Log before opening
        fd = os.open(abs_file_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only, prevent race conditions

        try:
            # Write the configuration data
            os.write(fd, important_config.encode('utf-8'))  # Encode to bytes
            logging.info(f"Successfully wrote to file: {abs_file_path}") # Log after writing
        finally:
            os.close(fd)  # Ensure the file descriptor is closed

        return True

    except OSError as e:
        logging.exception(f"Error writing to file: {e}") # Log the full exception
        print("Error writing to file.")  # Generic error for the user
        return False


# Example Usage:
# Define allowed extensions and locations
ALLOWED_EXTENSIONS = ['.conf', '.txt']
ALLOWED_LOCATIONS = ['/opt/myprogram/config']  # Only allow writing to this specific directory

# Configuration data
config_data = "important_config = value\nother_setting = another_value"

# Securely write the configuration
file_path = "/opt/myprogram/config/myconfig.conf"  # Example path
#file_path = "/opt/myprogram/config/subdir/myconfig.txt" # Example of writing to a subdirectory
#file_path = "./config/myconfig.txt" # Example relative path
#file_path = "/tmp/../../../../etc/passwd" # Example of path traversal attempt
#file_path = "/opt/myprogram/config/myconfig.exe" # Example of disallowed extension

if secure_write_config(file_path, config_data, ALLOWED_EXTENSIONS, ALLOWED_LOCATIONS):
    print("Configuration written successfully.")
else:
    print("Configuration write failed.")

