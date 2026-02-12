import os
import stat
import fcntl
import logging
import tempfile
import shutil

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def secure_write_config(config_data, file_path):
    """
    Securely writes configuration data to a file, preventing path traversal,
    limiting file size, and setting appropriate permissions.

    Args:
        config_data (str): The configuration data to write.
        file_path (str): The path to the configuration file.
    """

    # Security Guideline 1, 2, 14: Validate and sanitize file path, prevent path traversal, single dot
    if not isinstance(file_path, str):
        raise TypeError("File path must be a string.")

    if ".." in file_path:
        raise ValueError("Path traversal detected: '..' is not allowed in file paths.")

    if file_path.count(".") > 1:
        raise ValueError("File path contains more than one '.' character.")

    # Security Guideline 3: Use allowlist for file extensions and locations (example)
    allowed_extensions = ['.conf', '.cfg', '.ini']
    if not any(file_path.endswith(ext) for ext in allowed_extensions):
        logging.warning(f"File extension not in allowlist. Allowed extensions: {allowed_extensions}")
        # Consider raising an exception or using a default extension.
        # For now, we'll proceed with a warning.

    # Example: Restrict file location to a specific directory
    allowed_directory = "/opt/my_application/config/"
    if not file_path.startswith(allowed_directory):
        logging.warning(f"File path not in allowed directory. Allowed directory: {allowed_directory}")
        # Consider raising an exception or using a default directory.
        # For now, we'll proceed with a warning.

    # Security Guideline 4, 12: Implement proper file permissions and access controls
    # Set permissions: read/write for owner, read for group, read for others
    file_permissions = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH

    # Security Guideline 6: Ensure file is always closed
    try:
        # Create a temporary file in a secure location
        temp_file_dir = tempfile.mkdtemp(prefix="config_temp_", dir="/tmp")  # Ensure /tmp is secure
        temp_file_path = os.path.join(temp_file_dir, "temp_config")

        # Open the temporary file with the desired permissions
        file_descriptor = os.open(temp_file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, file_permissions)
        
        try:
            # Write the configuration data to the temporary file
            with open(file_descriptor, 'w') as temp_file:
                temp_file.write(config_data)

            # Atomically replace the original file with the temporary file
            shutil.move(temp_file_path, file_path)

            # Set permissions on the final file (redundant, but good practice)
            os.chmod(file_path, file_permissions)

            # Security Guideline 13: Prevent files from growing without limit
            max_file_size = 1024 * 1024  # 1MB limit
            if os.path.getsize(file_path) > max_file_size:
                logging.error("File size exceeds maximum allowed size.")
                raise ValueError("File size exceeds maximum allowed size.")

            logging.info(f"Successfully wrote configuration to {file_path}")

        except Exception as e:
            logging.error(f"Error writing configuration: {e}")
            raise
        finally:
            # Clean up the temporary directory
            shutil.rmtree(temp_file_dir)

    except OSError as e:
        logging.error(f"Error opening or creating file: {e}")
        raise

# Example usage:
if __name__ == '__main__':
    config_data = "important_config_data=some_value\n" \
                  "another_setting=another_value\n"
    
    # Example of a safe file path
    safe_file_path = "/opt/my_application/config/app.conf"

    try:
        secure_write_config(config_data, safe_file_path)
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    # Example of an unsafe file path (will raise an error)
    unsafe_file_path = "/tmp/../../etc/passwd"  # Path traversal attempt

    try:
        secure_write_config(config_data, unsafe_file_path)
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

