import os
import stat

def create_and_secure_file(filepath, content):
    """
    Creates a file, writes content to it, and sets restrictive permissions.

    Args:
        filepath (str): The path to the file to create.
        content (str): The content to write to the file.
    """

    # Validate filepath to prevent path traversal
    if ".." in filepath:
        raise ValueError("Invalid filepath: Path traversal detected.")

    # Define an allowlist of allowed file extensions (e.g., .txt, .dat)
    allowed_extensions = [".txt"]  # Example: only allow .txt files
    file_extension = os.path.splitext(filepath)[1]
    if file_extension not in allowed_extensions:
        raise ValueError(f"Invalid filepath: File extension '{file_extension}' not allowed.")

    try:
        # Create the file and write the content
        with open(filepath, "w") as f:
            f.write(content)

        # Set restrictive permissions (read/write for owner only)
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # Equivalent to 0o600

        print(f"File '{filepath}' created and secured successfully.")

    except OSError as e:
        print(f"Error creating or securing file: {e}")


if __name__ == "__main__":
    filepath = "secret.txt"
    content = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    create_and_secure_file(filepath, content)

