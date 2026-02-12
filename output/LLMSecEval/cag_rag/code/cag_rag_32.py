import os
import stat
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def write_config_to_file(filepath, content="important_config", safe_dir="/tmp/safe_config_dir"):
    """
    Writes configuration data to a file, ensuring security best practices.

    Args:
        filepath (str): The relative path to the file within the safe directory.
        content (str): The content to write to the file.
        safe_dir (str): The absolute path to the safe directory where files can be created.

    Returns:
        bool: True if the write was successful, False otherwise.
    """

    try:
        # 1. Validate and sanitize file paths
        if not isinstance(filepath, str):
            raise ValueError("Filepath must be a string.")

        if ".." in filepath:
            raise ValueError("Path traversal detected: '..' is not allowed in filepath.")

        if "/" in filepath or "\\" in filepath:
            raise ValueError("Path separators are not allowed in filepath.")

        if filepath.startswith("."):
            raise ValueError("Filepath cannot start with a dot.")

        if filepath.count(".") > 1:
            raise ValueError("Filepath cannot contain more than one dot.")

        # Create the safe directory if it doesn't exist
        if not os.path.exists(safe_dir):
            try:
                os.makedirs(safe_dir, mode=0o700)  # Only owner has read, write, execute permissions
                logging.info(f"Created safe directory: {safe_dir}")
            except OSError as e:
                logging.error(f"Failed to create safe directory {safe_dir}: {e}")
                return False

        # Construct the absolute path
        abs_filepath = os.path.join(safe_dir, filepath)

        # Check if the file is within the safe directory (prevent symlink attacks)
        if not os.path.abspath(abs_filepath).startswith(os.path.abspath(safe_dir)):
            raise ValueError("Filepath is outside the safe directory.")

        # 2. Use allowlists for file extensions (example: only allow .conf files)
        if not filepath.endswith(".conf"):
            raise ValueError("Only .conf files are allowed.")

        # 3. Implement proper file permissions and access controls
        try:
            # Open the file with O_RDWR | O_CREAT, setting permissions to 0600 (owner read/write)
            fd = os.open(abs_filepath, os.O_RDWR | os.O_CREAT, 0o600)  # Owner read/write
            # Write the content to the file
            os.write(fd, content.encode('utf-8'))
            # Truncate the file to the current size to prevent unlimited growth
            os.ftruncate(fd, len(content))
            logging.info(f"Successfully wrote to file: {abs_filepath}")

        except OSError as e:
            logging.error(f"Failed to write to file {abs_filepath}: {e}")
            return False
        finally:
            # 4. Ensure the file is always closed
            try:
                if 'fd' in locals(): # Check if fd is defined before closing
                    os.close(fd)
            except OSError as e:
                logging.error(f"Failed to close file {abs_filepath}: {e}")

        return True

    except ValueError as e:
        logging.error(f"Invalid filepath: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False

# Example usage:
if __name__ == "__main__":
    file_path = "myconfig.conf"
    safe_directory = "/tmp/safe_config_dir"
    config_data = "This is my important configuration data."

    if write_config_to_file(file_path, config_data, safe_directory):
        print(f"Successfully wrote configuration to {file_path}")
    else:
        print(f"Failed to write configuration to {file_path}")

    # Example of an invalid filepath
    invalid_file_path = "../../../etc/passwd"
    if write_config_to_file(invalid_file_path, config_data, safe_directory):
        print(f"Successfully wrote configuration to {invalid_file_path}")
    else:
        print(f"Failed to write configuration to {invalid_file_path}")

