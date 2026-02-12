import os

def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory.

    Args:
        filename: The name of the file to read.

    Returns:
        The content of the file as a string, or None if the file does not exist or an error occurs.
    """

    safe_directory = "/safe/"

    # 1. Input Validation:  Sanitize the filename to prevent path traversal attacks.
    #    - Check for "..", "/", and other potentially dangerous characters.
    #    - Consider using a whitelist of allowed characters.
    if ".." in filename or "/" in filename:
        print("Error: Invalid filename.  Filename cannot contain '..' or '/'.")
        return None

    # 2. Construct the full path to the file.
    filepath = os.path.join(safe_directory, filename)

    # 3. Check if the file exists.  This prevents potential errors if the file doesn't exist.
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' does not exist.")
        return None

    # 4. Check if the path is actually a file and not a directory.  This prevents reading directories.
    if not os.path.isfile(filepath):
        print(f"Error: '{filepath}' is not a file.")
        return None

    # 5.  Read the file content.  Use a try-except block to handle potential file I/O errors.
    try:
        with open(filepath, "r") as f:
            content = f.read()
        return content
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found (even after existence check).  This is unexpected.")
        return None
    except IOError as e:
        print(f"Error: An I/O error occurred while reading '{filepath}': {e}")
        return None
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
        return None


# Example usage:
if __name__ == "__main__":
    # Create a dummy file for testing (only if it doesn't exist)
    test_filename = "my_safe_file.txt"
    safe_directory = "/safe/"
    test_filepath = os.path.join(safe_directory, test_filename)

    if not os.path.exists(safe_directory):
        os.makedirs(safe_directory)  # Create the directory if it doesn't exist

    if not os.path.exists(test_filepath):
        with open(test_filepath, "w") as f:
            f.write("This is a test file in the /safe/ directory.\n")

    # Read the file
    file_content = read_safe_file(test_filename)

    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file.")

    # Test with an invalid filename (path traversal attempt)
    invalid_content = read_safe_file("../../../etc/passwd")  # Attempt to read a sensitive file
    if invalid_content is None:
        print("Successfully prevented path traversal.")

    # Test with a non-existent file
    nonexistent_content = read_safe_file("nonexistent_file.txt")
    if nonexistent_content is None:
        print("Successfully handled non-existent file.")

