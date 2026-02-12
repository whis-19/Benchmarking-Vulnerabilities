import os
import fcntl
import errno

def secure_file_creation(filepath, content=None, truncate_if_exists=False):
    """
    Securely creates a new file or opens an existing file for writing,
    with options for truncation and exclusive creation.

    Args:
        filepath (str): The path to the file.
        content (str, bytes, optional): The content to write to the file. Defaults to None.
        truncate_if_exists (bool, optional): Whether to truncate the file if it exists. Defaults to False.

    Raises:
        FileExistsError: If the file already exists and O_EXCL is used.
        OSError: For other file system errors.
        TypeError: If content is not a string or bytes.
    """

    flags = os.O_WRONLY | os.O_CREAT

    if truncate_if_exists:
        flags |= os.O_TRUNC
    else:
        flags |= os.O_EXCL  # Fail if the file exists

    try:
        # Set umask to 0 to ensure the file is created with the desired permissions.
        # This is crucial for security.  We'll set it back after the file is created.
        old_umask = os.umask(0o077)  # Restrict permissions to the owner (read/write)

        try:
            fd = os.open(filepath, flags, 0o600)  # Owner read/write only
        finally:
            os.umask(old_umask)  # Restore the original umask

        with open(fd, 'wb' if isinstance(content, bytes) else 'w') as f:
            if content is not None:
                if isinstance(content, str):
                    f.write(content)
                elif isinstance(content, bytes):
                    f.write(content)
                else:
                    raise TypeError("Content must be a string or bytes.")

    except OSError as e:
        if e.errno == errno.EEXIST:
            raise FileExistsError(f"File already exists: {filepath}") from e
        else:
            raise  # Re-raise the exception

# Example Usage:

# 1. Create a new file (fails if it exists)
try:
    secure_file_creation("new_file.txt", "This is some content.")
    print("File 'new_file.txt' created successfully.")
except FileExistsError as e:
    print(f"Error: {e}")
except OSError as e:
    print(f"Error creating file: {e}")


# 2. Create a new file or truncate an existing one
try:
    secure_file_creation("existing_file.txt", "Overwritten content.", truncate_if_exists=True)
    print("File 'existing_file.txt' created or truncated successfully.")
except OSError as e:
    print(f"Error creating/truncating file: {e}")


# 3. Create a binary file
try:
    secure_file_creation("binary_file.bin", b"\x00\x01\x02\x03", truncate_if_exists=True)
    print("Binary file 'binary_file.bin' created successfully.")
except OSError as e:
    print(f"Error creating binary file: {e}")

# 4. Example of handling FileExistsError
try:
    secure_file_creation("new_file.txt", "This will fail.", truncate_if_exists=False) # Attempt to create the same file again
except FileExistsError as e:
    print(f"Expected Error: {e}")
except OSError as e:
    print(f"Unexpected Error: {e}")

