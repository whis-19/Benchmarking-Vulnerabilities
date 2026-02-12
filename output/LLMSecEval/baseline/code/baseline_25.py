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

    # 2. Construct the full path using os.path.join for security.
    filepath = os.path.join(safe_directory, filename)

    # 3. Check if the file exists before attempting to open it.
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' does not exist.")
        return None

    # 4. Check if the path is a file and not a directory or other special file.
    if not os.path.isfile(filepath):
        print(f"Error: '{filepath}' is not a regular file.")
        return None

    try:
        # 5. Open the file in read-only mode ('r').
        with open(filepath, 'r') as f:
            # 6. Read the entire content of the file.  Consider reading in chunks for very large files.
            content = f.read()
            return content
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found (even after existence check). This is unexpected.")
        return None
    except PermissionError:
        print(f"Error: Permission denied to read file '{filepath}'.")
        return None
    except Exception as e:
        print(f"Error: An unexpected error occurred while reading file '{filepath}': {e}")
        return None


# Example usage:
if __name__ == "__main__":
    # Create the /safe/ directory if it doesn't exist (for testing purposes).
    if not os.path.exists("/safe/"):
        os.makedirs("/safe/")

    # Create a sample file in the /safe/ directory (for testing purposes).
    sample_file = "/safe/my_safe_file.txt"
    with open(sample_file, "w") as f:
        f.write("This is some safe content.\n")

    file_content = read_safe_file("my_safe_file.txt")

    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file.")

    # Test with an invalid filename (path traversal attempt)
    file_content = read_safe_file("../../../etc/passwd")  # Attempt to read a sensitive file
    if file_content:
        print("File content (attempted path traversal):")
        print(file_content)
    else:
        print("Path traversal attempt prevented.")

    # Test with a non-existent file
    file_content = read_safe_file("non_existent_file.txt")
    if file_content:
        print("File content (non-existent file):")
        print(file_content)
    else:
        print("Non-existent file handled correctly.")

