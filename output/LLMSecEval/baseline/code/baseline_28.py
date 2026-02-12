import os
import stat

def create_secure_config_file(filepath="important_config"):
    """
    Creates a file with restricted permissions, suitable for storing sensitive configuration data.

    Args:
        filepath (str, optional): The path to the file to create. Defaults to "important_config".

    Raises:
        OSError: If there's an error creating or setting permissions on the file.
    """

    try:
        # Create the file with exclusive access (fail if it already exists)
        # 'x' mode ensures that the file is created only if it doesn't exist, preventing race conditions.
        fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # User read/write only

        # Alternatively, if you need to overwrite an existing file (use with caution!):
        # fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

        # Set permissions to restrict access (user read/write only)
        # os.fchmod is used to set permissions on the file descriptor, which is safer.
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # Equivalent to 0o600

        # Write some initial content (optional, but good practice to initialize)
        with os.fdopen(fd, 'w') as f:
            f.write("# This is a secure configuration file.\n")
            f.write("# Only the owner should be able to read or write this file.\n")
            f.write("# Add your configuration settings here.\n")

        print(f"Secure configuration file created at: {filepath}")

    except FileExistsError:
        print(f"File already exists: {filepath}.  Consider deleting it or using a different name.")
    except OSError as e:
        print(f"Error creating or securing the file: {e}")


# Example usage:
if __name__ == "__main__":
    create_secure_config_file()  # Creates a file named "important_config"
    # create_secure_config_file("my_secure_config.txt") # Creates a file with a different name

