import os
import logging

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.INFO)

def is_path_safe(file_path, allowed_base_dir):
    """
    Checks if a file path is within the allowed base directory.

    Args:
        file_path: The path to check.
        allowed_base_dir: The allowed base directory.

    Returns:
        True if the path is safe, False otherwise.
    """
    try:
        # Normalize both paths to absolute paths
        abs_file_path = os.path.abspath(file_path)
        abs_allowed_base_dir = os.path.abspath(allowed_base_dir)

        # Check if the file path starts with the allowed base directory
        # and is not the same as the allowed base directory
        return os.path.commonpath([abs_allowed_base_dir, abs_file_path]) == abs_allowed_base_dir and abs_file_path != abs_allowed_base_dir

    except ValueError:
        logging.warning(f"Paths have no common prefix: file_path={file_path}, allowed_base_dir={allowed_base_dir}")
        return False  # Treat errors as unsafe
    except Exception as e:
        logging.exception(f"Error during path validation: file_path={file_path}, allowed_base_dir={allowed_base_dir}")
        return False  # Treat errors as unsafe

# Example usage:
allowed_dir = "/var/www/mywebapp"
file_path1 = "/var/www/mywebapp/uploads/image.jpg"
file_path2 = "/etc/passwd"
file_path3 = "/var/www/mywebapp/../config.ini"
file_path4 = "/var/www/mywebapp_config" # Example of commonpath issue

print(f"{file_path1}: {is_path_safe(file_path1, allowed_dir)}")
print(f"{file_path2}: {is_path_safe(file_path2, allowed_dir)}")
print(f"{file_path3}: {is_path_safe(file_path3, allowed_dir)}")
print(f"{file_path4}: {is_path_safe(file_path4, allowed_dir)}")

# Explanation to add to the original critique:
#
# "While `os.path.commonpath` is generally a good choice, it's important to note that it only checks for a *common prefix*.
#  It doesn't guarantee that the file is *within* the directory in a strict sense.  The updated `is_path_safe` function
#  now includes an additional check to ensure that the common path is exactly the allowed base directory and that the
#  file path is not the same as the allowed base directory.  This prevents cases where a path like '/var/www/mywebapp_config'
#  would be incorrectly considered safe."
#
# "Error logging has been improved by using the `logging` module to record exceptions with tracebacks.  This provides
#  more detailed information for debugging path validation issues."

