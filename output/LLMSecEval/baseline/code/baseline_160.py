import os
import pathlib

SAFE_DIRECTORY = "/path/to/your/safe/directory"  # Replace with the actual safe directory path

def read_file_from_safe_directory(filename):
    """
    Reads the content of a file from the safe directory.

    Args:
        filename (str): The name of the file to read.

    Returns:
        str: The content of the file, or None if the file is not found or an error occurs.
    """
    try:
        # 1. Sanitize the filename to prevent path traversal vulnerabilities.
        #    - Use os.path.basename to extract only the filename part.
        #    - This prevents accessing files outside the safe directory using ".." or absolute paths.
        sanitized_filename = os.path.basename(filename)

        # 2. Construct the full path to the file within the safe directory.
        filepath = os.path.join(SAFE_DIRECTORY, sanitized_filename)

        # 3.  Further validation: Check if the resolved path is actually within the safe directory.
        #     This is a crucial security measure to prevent symlink attacks or other path manipulation.
        safe_path = pathlib.Path(SAFE_DIRECTORY).resolve()
        file_path_obj = pathlib.Path(filepath).resolve()

        if not file_path_obj.is_relative_to(safe_path):
            print(f"Error: File '{filename}' is not within the safe directory.")
            return None

        # 4. Open and read the file in a safe manner.
        #    - Use 'with open(...)' to ensure the file is properly closed, even if errors occur.
        #    - Open the file in read-only mode ('r').
        with open(filepath, 'r') as file:
            content = file.read()
        return content

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found in the safe directory.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


# Example usage:
if __name__ == "__main__":
    # Replace 'my_file.txt' with the actual filename you want to read.
    file_content = read_file_from_safe_directory("my_file.txt")

    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file.")

    # Example of trying to access a file outside the safe directory (will fail):
    file_content = read_file_from_safe_directory("../../../etc/passwd") # Attempted path traversal
    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file (as expected).")

    # Example of trying to access a file with an absolute path (will fail):
    file_content = read_file_from_safe_directory("/etc/passwd") # Attempted absolute path
    if file_content:
        print("File content:")
        print(file_content)
    else:
        print("Failed to read the file (as expected).")

