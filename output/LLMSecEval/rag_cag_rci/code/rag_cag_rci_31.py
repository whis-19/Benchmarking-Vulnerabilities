import os
import stat
from typing import Optional

SAFE_FOLDER = "/tmp/safe_files"  # Define a safe directory
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit


def secure_file_creation(filename: str, data: str) -> Optional[str]:
    """
    Creates a new file securely, preventing common file-related vulnerabilities.

    Args:
        filename: The name of the file to create (without path).
        data: The data to write to the file.

    Returns:
        The absolute path of the created file if successful, None otherwise.
    """

    if not filename:
        print("Error: Filename cannot be empty.")
        return None

    if "/" in filename or "\\" in filename or ".." in filename:
        print("Error: Filename contains invalid characters or sequences.")
        return None

    if filename.count(".") > 1:
        print("Error: Filename contains too many '.' characters.")
        return None

    if not filename.isalnum():
        print("Error: Filename contains invalid characters. Only alphanumeric characters are allowed.")
        return None

    if not os.path.exists(SAFE_FOLDER):
        try:
            os.makedirs(SAFE_FOLDER, mode=0o700)  # Create with restricted permissions
        except OSError as e:
            print(f"Error creating safe directory: {e}")
            return None

    filepath = os.path.join(SAFE_FOLDER, filename)

    # Check if the normalized path is safe
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(SAFE_FOLDER):
        print("Error: Filepath is outside the safe directory.")
        return None

    if ".." in normalized_path[len(SAFE_FOLDER):]:
        print("Error: Filepath contains '..' sequence after normalization.")
        return None

    try:
        # Use os.open with O_CREAT, O_EXCL, O_WRONLY for secure file creation
        fd = os.open(filepath, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)  # Create, fail if exists, write-only, restricted permissions
        with open(fd, 'w') as f:  # Open file descriptor
            if len(data) > MAX_FILE_SIZE:
                print("Error: Data exceeds maximum file size limit.")
                return None

            f.write(data)
            f.flush()  # Ensure data is written to disk
            os.fsync(f.fileno())  # Ensure data is written to disk
        return filepath

    except FileExistsError:
        print("Error: File already exists.")
        return None
    except OSError as e:
        print(f"Error creating or writing to file: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage:
    file_name = "my_safe_file.txt"
    file_content = "This is some safe content for the file."

    created_file_path = secure_file_creation(file_name, file_content)

    if created_file_path:
        print(f"File created successfully at: {created_file_path}")

        # Example of reading the file (for verification)
        try:
            with open(created_file_path, 'r') as f:
                read_content = f.read()
                print(f"Content of the file: {read_content}")
        except OSError as e:
            print(f"Error reading the file: {e}")
    else:
        print("File creation failed.")

    # Example of a failed attempt due to invalid filename
    file_name_invalid = "../unsafe_file.txt"
    created_file_path = secure_file_creation(file_name_invalid, file_content)
    if created_file_path:
        print(f"File created successfully at: {created_file_path}")
    else:
        print("File creation failed.")

