import os
from werkzeug.utils import secure_filename

SAFE_DIRECTORY = "/path/to/safe/directory"  # Replace with your actual safe directory
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv'}  # Example: Allow only these file types

def is_safe_path(basedir, path, filename):
    """
    Checks if the given path is safe and within the allowed base directory.
    Uses secure_filename to sanitize the filename.

    Args:
        basedir: The base directory to restrict access to.
        path: The user-provided path (relative to basedir).
        filename: The filename to check.

    Returns:
        True if the path is safe, False otherwise.
    """
    if not filename:
        return False

    if not isinstance(filename, str):
        return False

    if not isinstance(path, str):
        return False

    if ".." in path:
        return False

    if "/" in path or "\\" in path:
        return False

    if filename.count(".") > 1:
        return False

    filename = secure_filename(filename)
    if not filename:
        return False

    filepath = os.path.join(basedir, path, filename)
    filepath = os.path.normpath(filepath)

    if not filepath.startswith(basedir):
        return False

    return True


def allowed_file(filename):
    """
    Checks if the file extension is allowed.

    Args:
        filename: The name of the file.

    Returns:
        True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def read_file_from_safe_directory(path, filename):
    """
    Reads a file from the safe directory, ensuring the path is safe.

    Args:
        path: The user-provided path (relative to SAFE_DIRECTORY).
        filename: The name of the file to read.

    Returns:
        The content of the file as a string, or None if the file could not be read.
    """

    if not is_safe_path(SAFE_DIRECTORY, path, filename):
        print("Error: Unsafe path or filename.")
        return None

    if not allowed_file(filename):
        print("Error: File type not allowed.")
        return None

    filepath = os.path.join(SAFE_DIRECTORY, path, filename)

    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        return None
    except IOError as e:
        print(f"Error: Could not read file: {filepath} - {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


# Example usage:
if __name__ == '__main__':
    # Example 1: Safe path
    file_content = read_file_from_safe_directory("", "safe_file.txt")  # Assuming safe_file.txt exists in SAFE_DIRECTORY
    if file_content:
        print("File content:\n", file_content)

    # Example 2: Unsafe path (contains "..")
    file_content = read_file_from_safe_directory("../", "safe_file.txt")
    if file_content:
        print("File content:\n", file_content)  # This should not be printed

    # Example 3: Unsafe path (contains "/")
    file_content = read_file_from_safe_directory("subdir/", "safe_file.txt")
    if file_content:
        print("File content:\n", file_content)  # This should not be printed

    # Example 4: Unsafe filename (contains "..")
    file_content = read_file_from_safe_directory("", "..safe_file.txt")
    if file_content:
        print("File content:\n", file_content)  # This should not be printed

    # Example 5: Unsafe filename (contains "/")
    file_content = read_file_from_safe_directory("", "safe/file.txt")
    if file_content:
        print("File content:\n", file_content)  # This should not be printed

    # Example 6: Safe path with subdirectory
    file_content = read_file_from_safe_directory("subdir", "safe_file.txt") # Assuming safe_file.txt exists in SAFE_DIRECTORY/subdir
    if file_content:
        print("File content:\n", file_content)

    # Example 7: Unsafe file type
    file_content = read_file_from_safe_directory("", "safe_file.exe")
    if file_content:
        print("File content:\n", file_content)  # This should not be printed

    # Example 8: Safe filename with multiple dots
    file_content = read_file_from_safe_directory("", "safe.file.txt")
    if file_content:
        print("File content:\n", file_content)

