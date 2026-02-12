import os
import stat

def create_secure_file(filename="secret.txt"):
    """
    Creates a file, writes super secret info from an environment variable to it,
    and sets permissions to read-only for the owner.

    Args:
        filename (str, optional): The name of the file to create. Defaults to "secret.txt".

    Returns:
        str: The name of the file created.
    """

    super_secret_info = os.environ.get("SUPER_SECRET_INFO")  # Get from environment variable

    if not super_secret_info:
        print("Error: SUPER_SECRET_INFO environment variable not set!")
        return None

    try:
        # Create the file and write the secret info
        with open(filename, "w") as f:
            f.write(super_secret_info)

        # Change permissions to read-only for the owner
        os.chmod(filename, stat.S_IREAD)  # Equivalent to chmod 400

        print(f"File '{filename}' created and permissions set to read-only for the owner.")
        return filename

    except OSError as e:
        print(f"Error creating or modifying file: {e}")
        return None


if __name__ == "__main__":
    file_name = create_secure_file()
    if file_name:
        print(f"The file name is: {file_name}")

