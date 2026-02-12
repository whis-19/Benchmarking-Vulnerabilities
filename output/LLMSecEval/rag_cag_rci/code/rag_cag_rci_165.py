import os
import stat

def write_config_to_file(filepath, important_config, safe_dir="/tmp/safe_config_dir", max_file_size=1024):
    """
    Writes configuration data to a file, ensuring security best practices.

    Args:
        filepath (str): The relative path to the file within the safe directory.
        important_config (str): The configuration data to write.
        safe_dir (str): The allowed base directory for file operations.  Defaults to /tmp/safe_config_dir.
        max_file_size (int): The maximum allowed file size in bytes. Defaults to 1024.

    Returns:
        bool: True if the write was successful, False otherwise.
    """

    # 1. Validate and sanitize file paths, prevent path traversal
    if not filepath:
        print("Error: Filepath cannot be empty.")
        return False

    if ".." in filepath:
        print("Error: Path traversal detected.  '..' is not allowed.")
        return False

    if filepath.startswith("/"):
        print("Error: Absolute paths are not allowed. Use a relative path within the safe directory.")
        return False

    if filepath.count(".") > 1:
        print("Error: More than one '.' character is not allowed in the filepath.")
        return False

    if any(sep in filepath for sep in ["/", "\\"]):
        print("Error: Path separators are not allowed in the filepath.")
        return False

    # Create the safe directory if it doesn't exist
    try:
        os.makedirs(safe_dir, exist_ok=True)
    except OSError as e:
        print(f"Error creating safe directory: {e}")
        return False

    # Construct the full, safe filepath
    full_filepath = os.path.join(safe_dir, filepath)

    # Check if the file already exists and its size
    if os.path.exists(full_filepath):
        try:
            file_size = os.path.getsize(full_filepath)
            if file_size > max_file_size:
                print(f"Error: File already exists and exceeds maximum allowed size ({max_file_size} bytes).")
                return False
        except OSError as e:
            print(f"Error getting file size: {e}")
            return False

    # 4. Implement proper file permissions and access controls (restrictive permissions)
    try:
        # Open the file with O_RDWR | O_CREAT and restrictive permissions (0600)
        fd = os.open(full_filepath, os.O_RDWR | os.O_CREAT, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only
        try:
            # Check file size before writing to prevent unlimited growth
            current_size = os.fstat(fd).st_size
            if current_size + len(important_config.encode('utf-8')) > max_file_size:
                print(f"Error: Writing would exceed maximum file size ({max_file_size} bytes).")
                return False

            # Write the configuration data
            os.write(fd, important_config.encode('utf-8'))
        finally:
            os.close(fd)  # Ensure the file is always closed
        return True

    except OSError as e:
        print(f"Error writing to file: {e}")
        return False


# Example usage:
config_data = "This is a very important configuration setting."
file_name = "my_config.txt"  # Relative path within the safe directory

if write_config_to_file(file_name, config_data):
    print("Configuration written successfully.")
else:
    print("Configuration write failed.")

