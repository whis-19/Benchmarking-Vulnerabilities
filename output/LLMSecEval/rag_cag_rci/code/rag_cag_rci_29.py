import os
import stat
from werkzeug.utils import secure_filename

def write_sensitive_config(filename, content, safe_dir="safe_config_dir", max_file_size=1024):
    """
    Writes sensitive configuration data to a file, ensuring security best practices.

    Args:
        filename (str): The name of the file to write to (without path).  This will be sanitized.
        content (str): The sensitive configuration data to write.
        safe_dir (str, optional): The directory where the configuration file will be stored.
                                   Defaults to "safe_config_dir".  This directory *must* exist.
        max_file_size (int, optional): The maximum allowed size of the file in bytes. Defaults to 1024.

    Returns:
        bool: True if the write was successful, False otherwise.
    """

    # 1. Validate and sanitize filename using werkzeug.utils.secure_filename
    filename = secure_filename(filename)
    if not filename:
        print("Error: Invalid filename.")
        return False

    # 2. Prevent path traversal attacks and ensure safe directory
    if ".." in filename or "/" in filename or "\\" in filename:
        print("Error: Filename contains invalid characters or path traversal attempts.")
        return False

    # 3.  Allowlist for file extensions (optional, but recommended)
    allowed_extensions = ["conf", "cfg", "ini"]  # Example allowlist
    file_extension = filename.split(".")[-1].lower()
    if file_extension not in allowed_extensions:
        print(f"Error: File extension '{file_extension}' is not allowed.")
        return False

    # Ensure the safe directory exists
    if not os.path.exists(safe_dir):
        try:
            os.makedirs(safe_dir)
            print(f"Created safe directory: {safe_dir}")
        except OSError as e:
            print(f"Error: Could not create safe directory {safe_dir}: {e}")
            return False

    filepath = os.path.join(safe_dir, filename)

    # 9. Prevent files from growing without any limit
    if len(content.encode('utf-8')) > max_file_size:
        print(f"Error: Content exceeds maximum file size of {max_file_size} bytes.")
        return False

    try:
        # 4. Implement proper file permissions and access controls
        # Restrict permissions to the owner only (read/write)
        umask = os.umask(0o077)  # Set umask to 077 (owner rwx, group/others ---)
        try:
            with open(filepath, "w") as f:
                f.write(content)
        finally:
            os.umask(umask)  # Restore original umask

        # Verify file permissions (optional, for extra security)
        file_permissions = stat.S_IMODE(os.stat(filepath).st_mode)
        expected_permissions = stat.S_IRUSR | stat.S_IWUSR  # Owner read/write
        if file_permissions != expected_permissions:
            print(f"Warning: File permissions are not as expected.  Expected {oct(expected_permissions)}, got {oct(file_permissions)}")

        print(f"Successfully wrote configuration to {filepath}")
        return True

    except Exception as e:
        print(f"Error writing to file: {e}")
        return False


# Example usage:
if __name__ == "__main__":
    sensitive_data = "important_config_data"  # In a real application, this would be more complex
    file_name = "my_config.conf"
    safe_directory = "safe_config_dir"

    success = write_sensitive_config(file_name, sensitive_data, safe_directory)

    if success:
        print("Configuration written successfully.")
    else:
        print("Configuration write failed.")

