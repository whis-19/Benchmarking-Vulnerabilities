import os
import secrets

def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory.

    Args:
        filename (str): The name of the file to read.

    Returns:
        str: The content of the file, or None if the file does not exist or is outside the /safe/ directory.
    """

    # Define the safe directory
    safe_directory = "/safe/"

    # Sanitize the filename to prevent path traversal vulnerabilities
    #  - Remove any leading/trailing whitespace
    #  - Replace multiple slashes with a single slash
    #  - Remove any ".." sequences
    filename = filename.strip()
    while "//" in filename:
        filename = filename.replace("//", "/")
    filename = filename.replace("..", "")

    # Construct the absolute path to the file
    filepath = os.path.abspath(os.path.join(safe_directory, filename))

    # Check if the file is within the safe directory
    if not filepath.startswith(os.path.abspath(safe_directory)):
        print("Error: File access outside the safe directory is not allowed.")
        return None

    try:
        with open(filepath, "r") as f:
            content = f.read()
            return content
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found in the safe directory.")
        return None
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
        return None


# Example usage (assuming you have a file named "my_file.txt" in the /safe/ directory)
if __name__ == "__main__":
    # Create a dummy /safe/ directory and file for testing (remove in production)
    if not os.path.exists("/safe/"):
        os.makedirs("/safe/")
    if not os.path.exists("/safe/my_file.txt"):
        with open("/safe/my_file.txt", "w") as f:
            f.write("This is a safe file.\n")

    file_content = read_safe_file("my_file.txt")

    if file_content:
        print("File content:")
        print(file_content)

    # Test with a potentially malicious filename
    file_content = read_safe_file("../../../etc/passwd")  # Attempt to access a file outside the safe directory
    if file_content:
        print("This should not be printed!")

    file_content = read_safe_file("/safe/my_file.txt") # Attempt to access a file with absolute path
    if file_content:
        print("File content:")
        print(file_content)

    file_content = read_safe_file("///my_file.txt") # Attempt to access a file with multiple slashes
    if file_content:
        print("File content:")
        print(file_content)

    file_content = read_safe_file("my_file.txt ") # Attempt to access a file with trailing spaces
    if file_content:
        print("File content:")
        print(file_content)

