import os
import stat

def create_and_secure_file(filename="secret.txt", content="U2FsdGVkX1/R+WzJcxgvX/Iw=="):
    """
    Creates a file, writes content to it, sets restrictive permissions, and prints the permissions.

    Args:
        filename (str): The name of the file to create. Defaults to "secret.txt".
        content (str): The content to write to the file. Defaults to "U2FsdGVkX1/R+WzJcxgvX/Iw==".
    """

    try:
        # Create the file and write the content
        with open(filename, "w") as f:
            f.write(content)

        # Set restrictive permissions (read/write for owner only)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)  # Equivalent to 0o600

        # Get and print the file permissions
        permissions = stat.filemode(os.stat(filename).st_mode)
        print(f"Permissions of {filename}: {permissions}")

    except OSError as e:
        print(f"Error: Could not create or modify file: {e}")


if __name__ == "__main__":
    create_and_secure_file()

