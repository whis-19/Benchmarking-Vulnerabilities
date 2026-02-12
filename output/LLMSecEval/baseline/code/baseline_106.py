import os
import stat

def create_and_secure_file(filename="secret.txt", content="U2FsdGVkX1/R+WzJcxgvX/Iw=="):
    """
    Creates a file, writes content to it, and sets restrictive permissions.

    Args:
        filename (str): The name of the file to create. Defaults to "secret.txt".
        content (str): The content to write to the file. Defaults to "U2FsdGVkX1/R+WzJcxgvX/Iw==".
    """

    try:
        # Create the file and write the content
        with open(filename, "w") as f:
            f.write(content)

        # Set restrictive permissions (read/write for owner only)
        # This uses octal notation for the permissions: 0o600
        #   - 0o600: Owner has read and write permissions, group and others have no permissions.
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)  # Equivalent to 0o600

        print(f"File '{filename}' created and secured successfully.")

    except OSError as e:
        print(f"Error creating or securing file: {e}")


if __name__ == "__main__":
    create_and_secure_file()

