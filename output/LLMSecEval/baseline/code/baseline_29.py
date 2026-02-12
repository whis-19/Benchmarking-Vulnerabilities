import os
import stat

def write_secure_config(filename="important_config", content="important_config"):
    """
    Writes the given content to a file with restricted permissions.

    Args:
        filename (str, optional): The name of the file to create/write to. Defaults to "important_config".
        content (str, optional): The content to write to the file. Defaults to "important_config".

    Raises:
        OSError: If there's an error creating or writing to the file, or setting permissions.
    """

    try:
        # Open the file in write mode ('w')
        # 'x' ensures the file is created only if it doesn't exist.  This prevents accidental overwrites.
        # 'encoding' specifies UTF-8 for consistent character handling.
        with open(filename, 'x', encoding='utf-8') as f:
            f.write(content)

        # Set file permissions to read/write for the owner only (400 + 200 = 600 in octal)
        # This is the most secure option for sensitive configuration files.
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)  # Equivalent to chmod 600

    except FileExistsError:
        print(f"Error: File '{filename}' already exists.  Choose a different filename or handle existing files carefully.")
    except OSError as e:
        print(f"Error writing to or setting permissions on file '{filename}': {e}")
        raise  # Re-raise the exception to signal failure to the caller.


if __name__ == '__main__':
    try:
        write_secure_config()  # Use default filename and content
        print("Configuration file created and secured successfully.")
    except OSError:
        print("Failed to create and secure the configuration file.")

