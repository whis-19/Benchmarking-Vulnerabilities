import os
import errno

def secure_file_creation(filepath, data, safe_dir="/tmp/safe_files", max_file_size=1024):
    """
    Creates a new file or truncates an existing file for writing, with security checks.

    Args:
        filepath (str): The name of the file to create or truncate (without path).
        data (str): The data to write to the file.
        safe_dir (str): The directory where files are allowed to be created.  Defaults to /tmp/safe_files.
        max_file_size (int): The maximum allowed file size in bytes. Defaults to 1024.

    Returns:
        bool: True if the file was successfully created/truncated and written to, False otherwise.
    """

    # Validate filepath
    if not filepath:
        print("Error: Filepath cannot be empty.")
        return False

    if "/" in filepath or "\\" in filepath:
        print("Error: Filepath cannot contain directory separators.")
        return False

    if ".." in filepath:
        print("Error: Filepath cannot contain '..' sequences.")
        return False

    if filepath.count(".") > 1:
        print("Error: Filepath cannot contain more than one '.' character.")
        return False

    # Create safe directory if it doesn't exist
    if not os.path.exists(safe_dir):
        try:
            os.makedirs(safe_dir, exist_ok=True)  # Create directory if it doesn't exist
        except OSError as e:
            print(f"Error creating safe directory: {e}")
            return False

    # Construct the full, safe filepath
    full_filepath = os.path.join(safe_dir, filepath)

    # Check if the file already exists.  If so, fail.
    if os.path.exists(full_filepath):
        print("Error: File already exists.")
        return False

    # Check file size before writing
    if len(data) > max_file_size:
        print(f"Error: Data size exceeds maximum allowed file size of {max_file_size} bytes.")
        return False

    try:
        # Open the file with O_CREAT, O_TRUNC, O_WRONLY, and O_EXCL flags
        fd = os.open(full_filepath, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_EXCL, 0o600)  # Permissions: rw-------
        try:
            # Write the data to the file
            os.write(fd, data.encode('utf-8'))
        finally:
            # Ensure the file is always closed
            os.close(fd)
        return True
    except OSError as e:
        if e.errno == errno.EEXIST:
            print("Error: File already exists (race condition).")
        else:
            print(f"Error creating or writing to file: {e}")
        return False

