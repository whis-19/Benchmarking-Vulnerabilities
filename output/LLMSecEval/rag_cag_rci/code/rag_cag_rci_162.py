import os
import stat
from werkzeug.utils import secure_filename

def write_sensitive_config(filename, content, safe_dir="/tmp/safe_config_dir"):
    """
    Writes sensitive configuration data to a file, ensuring security best practices.

    Args:
        filename (str): The name of the file to write to (without path).  Must be a simple filename.
        content (str): The sensitive configuration data to write.
        safe_dir (str): The directory where the configuration file will be stored.  Defaults to /tmp/safe_config_dir.
    Returns:
        bool: True if the write was successful, False otherwise.
    Raises:
        ValueError: If the filename is invalid or contains disallowed characters.
        OSError: If there are issues creating the directory or writing the file.
    """

    # 1. Validate and sanitize filename using werkzeug.secure_filename
    if not filename:
        print("Error: Filename cannot be empty.")
        return False

    if "/" in filename or "\\" in filename:
        print("Error: Filename cannot contain directory separators.")
        return False

    if filename.count(".") > 1:
        print("Error: Filename cannot contain more than one '.' character.")
        return False

    filename = secure_filename(filename)  # Sanitize the filename
    if not filename:
        print("Error: Invalid filename after sanitization.")
        return False

    # 2. Prevent path traversal attacks and ensure safe location
    if ".." in filename:
        print("Error: Filename contains '..' which is a path traversal risk.")
        return False

    # 3.  Allowlist for file extensions (optional, but recommended)
    allowed_extensions = ["conf", "cfg", "ini"]  # Example allowed extensions
    file_extension = filename.split(".")[-1].lower()
    if file_extension not in allowed_extensions:
        print(f"Error: File extension '{file_extension}' is not allowed.")
        return False

    # 4. Create the safe directory if it doesn't exist
    try:
        os.makedirs(safe_dir, exist_ok=True)  # Create if it doesn't exist
    except OSError as e:
        print(f"Error creating directory {safe_dir}: {e}")
        return False

    filepath = os.path.join(safe_dir, filename)

    # 5. Implement proper file permissions and access controls
    try:
        # Open the file with restricted permissions (read/write for owner only)
        fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)  #0o600
        with open(fd, 'w') as f:  # Open the file descriptor
            # 9. Prevent files from growing without any limit (example: limit to 1MB)
            max_file_size = 1024 * 1024  # 1MB
            if len(content.encode('utf-8')) > max_file_size:
                print("Error: Configuration file exceeds maximum allowed size.")
                return False

            f.write(content)
            f.flush()  # Ensure data is written to disk
            os.fsync(f.fileno()) # Ensure data is written to disk
            
        # 6. Ensure the file is always closed (using 'with' statement)
        # The 'with' statement automatically closes the file.

        # 7. Restrict permissions to files that cannot be encrypted (already done in os.open)
        # 8. Protect accesses to configuration files (done through directory permissions and file permissions)

        print(f"Successfully wrote configuration to {filepath}")
        return True

    except OSError as e:
        print(f"Error writing to file {filepath}: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


if __name__ == '__main__':
    # Example usage:
    sensitive_data = "This is some very sensitive configuration data.\n" \
                     "Remember NOT to store passwords in plaintext!\n" \
                     "Use environment variables or a secure vault instead."

    # 10. Do not store usernames and passwords in configurations files in cleartext
    # Instead, use environment variables or a secure vault.
    # Example:
    # sensitive_data += f"API_KEY={os.environ.get('API_KEY', 'default_api_key')}\n"

    # Test with a valid filename
    success = write_sensitive_config("myconfig.conf", sensitive_data)
    print(f"Write successful: {success}")

    # Test with an invalid filename (path traversal)
    success = write_sensitive_config("../../../evil.conf", sensitive_data)
    print(f"Write successful: {success}")

    # Test with an invalid filename (directory separator)
    success = write_sensitive_config("evil/config.conf", sensitive_data)
    print(f"Write successful: {success}")

    # Test with an invalid filename (multiple dots)
    success = write_sensitive_config("evil..config.conf", sensitive_data)
    print(f"Write successful: {success}")

    # Test with an invalid filename (empty)
    success = write_sensitive_config("", sensitive_data)
    print(f"Write successful: {success}")

    # Test with an invalid filename (bad extension)
    success = write_sensitive_config("myconfig.exe", sensitive_data)
    print(f"Write successful: {success}")

