import os
import stat
import logging

# Configure logging (optional, but recommended for security)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for security
SAFE_FOLDER = "/app/config"  # Define a safe directory
ALLOWED_EXTENSIONS = [".conf", ".txt"]  # Define allowed file extensions
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit (adjust as needed)

def write_config_to_file(filename, config_data):
    """
    Writes configuration data to a file, ensuring security best practices.

    Args:
        filename (str): The name of the file to write to.
        config_data (str): The configuration data to write.

    Returns:
        bool: True if the write was successful, False otherwise.
    """

    if not isinstance(filename, str):
        logging.error("Filename must be a string.")
        return False

    if not isinstance(config_data, str):
        logging.error("Config data must be a string.")
        return False

    # 1. Validate and sanitize file paths
    # 2. Prevent path traversal attacks
    if ".." in filename:
        logging.error("Filename contains '..' which is a path traversal attempt.")
        return False

    if filename.count(".") > 1:
        logging.error("Filename contains more than one '.' character.")
        return False

    if any(sep in filename for sep in ["/", "\\"]):
        logging.error("Filename contains path separators.")
        return False

    if not filename:
        logging.error("Filename is empty.")
        return False

    # 3. Use allowlists for file extensions
    file_extension = os.path.splitext(filename)[1]
    if file_extension not in ALLOWED_EXTENSIONS:
        logging.error(f"File extension '{file_extension}' is not allowed.")
        return False

    # Construct the full file path
    filepath = os.path.join(SAFE_FOLDER, filename)

    # Ensure the safe folder exists
    if not os.path.exists(SAFE_FOLDER):
        try:
            os.makedirs(SAFE_FOLDER, exist_ok=True)  # Create if it doesn't exist
        except OSError as e:
            logging.error(f"Failed to create safe folder: {e}")
            return False

    # Check if the filepath is within the safe folder
    if not os.path.abspath(filepath).startswith(os.path.abspath(SAFE_FOLDER)):
        logging.error("Filepath is not within the safe folder.")
        return False

    # 6. Prevent files from growing without any limit
    if len(config_data) > MAX_FILE_SIZE:
        logging.error("Config data exceeds the maximum allowed file size.")
        return False

    try:
        # Open the file in write mode ('w') - overwrites existing content
        with open(filepath, 'w') as f:
            f.write(config_data)

        # 4. Implement proper file permissions and access controls (restrictive)
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only

        logging.info(f"Successfully wrote config to {filepath}")
        return True

    except OSError as e:
        logging.error(f"Error writing to file: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False


# Example usage (demonstrates secure usage)
if __name__ == '__main__':
    config_data = "important_config_data=123\n"  # Example config
    filename = "myconfig.conf"  # Example filename

    if write_config_to_file(filename, config_data):
        print("Config written successfully.")
    else:
        print("Config write failed.")

    # Example of an attempted path traversal attack (will fail)
    if write_config_to_file("../../../evil.conf", "evil_config"):
        print("Evil config written (this should not happen!).")
    else:
        print("Evil config write prevented (as expected).")

    # Example of an invalid file extension (will fail)
    if write_config_to_file("myconfig.exe", "malicious_code"):
        print("Malicious config written (this should not happen!).")
    else:
        print("Malicious config write prevented (as expected).")

