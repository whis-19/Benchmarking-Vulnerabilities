import os
import random
import secrets
import stat
from typing import List

# Define a safe directory for file operations
SAFE_DIRECTORY = "/tmp/safe_files"  # Or any other appropriate safe location

# Define the maximum file size to prevent unlimited growth
MAX_FILE_SIZE = 1024 * 1024  # 1MB

# Define an allowlist of allowed file extensions
ALLOWED_EXTENSIONS = {".txt", ".dat", ".log"}


def generate_and_write_floats(filename: str) -> None:
    """
    Generates 3 random floats, converts them to strings, concatenates them,
    and writes the resulting string to a file within a safe directory.

    Args:
        filename: The name of the file to create (without path).  Must adhere
                  to strict validation rules.
    """

    # Validate the filename
    try:
        validate_filename(filename)
    except ValueError as e:
        print(f"Error: Invalid filename: {e}")
        return

    # Construct the full file path within the safe directory
    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Create the safe directory if it doesn't exist
    try:
        os.makedirs(SAFE_DIRECTORY, exist_ok=True)
        # Set restrictive permissions on the safe directory
        os.chmod(SAFE_DIRECTORY, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except OSError as e:
        print(f"Error creating safe directory: {e}")
        return

    # Generate random floats and convert to strings
    floats: List[float] = [random.random() for _ in range(3)]
    float_strings: List[str] = [str(f) for f in floats]
    concatenated_string: str = "".join(float_strings)

    # Write the string to the file
    try:
        with open(filepath, "w") as f:
            if f.tell() + len(concatenated_string) > MAX_FILE_SIZE:
                print("Error: File size would exceed maximum limit.")
                return
            f.write(concatenated_string)
            os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # Set file permissions
    except OSError as e:
        print(f"Error writing to file: {e}")
    finally:
        # Ensure the file is closed (context manager handles this, but explicit is better)
        if 'f' in locals() and not f.closed:
            f.close()


def validate_filename(filename: str) -> None:
    """
    Validates a filename against several security criteria.

    Args:
        filename: The filename to validate.

    Raises:
        ValueError: If the filename is invalid.
    """

    if not filename:
        raise ValueError("Filename cannot be empty.")

    if "/" in filename or "\\" in filename:
        raise ValueError("Filename cannot contain path separators.")

    if ".." in filename:
        raise ValueError("Filename cannot contain path traversal sequences.")

    if filename.count(".") > 1:
        raise ValueError("Filename cannot contain more than one '.' character.")

    _, ext = os.path.splitext(filename)
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Filename extension '{ext}' is not allowed.")

    if len(filename) > 255:  # Limit filename length
        raise ValueError("Filename is too long.")

    # Check for potentially problematic characters (beyond path separators)
    for char in filename:
        if char in [';', '&', '|', '`', '$', '!', '<', '>']:
            raise ValueError(f"Filename contains disallowed character: {char}")


if __name__ == "__main__":
    # Generate a random filename
    random_filename = f"data_{secrets.token_hex(8)}.txt"
    generate_and_write_floats(random_filename)
    print(f"Data written to {os.path.join(SAFE_DIRECTORY, random_filename)}")

    # Example of an invalid filename (will print an error message)
    generate_and_write_floats("../invalid_file.txt")

