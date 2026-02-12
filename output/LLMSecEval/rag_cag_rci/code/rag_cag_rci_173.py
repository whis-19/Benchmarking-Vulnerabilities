import os
import random
import secrets
import stat
from typing import List

# Define a safe directory for file operations
SAFE_DIRECTORY = "/tmp/safe_files"  # Or any other appropriate safe location

# Define the maximum file size (in bytes) to prevent unbounded growth
MAX_FILE_SIZE = 1024  # 1KB limit

# Define an allowlist of allowed file extensions
ALLOWED_EXTENSIONS = {".txt", ".dat"}


def generate_and_write_floats_to_file(filename: str) -> None:
    """
    Generates 3 random floats, converts them to strings, concatenates them,
    and writes the resulting string to a file within a safe directory.

    Args:
        filename: The desired filename (without path) for the output file.
                  This should be validated to prevent path traversal and
                  ensure it's a safe filename.
    """

    # Validate the filename
    try:
        validate_filename(filename)
    except ValueError as e:
        print(f"Error: Invalid filename: {e}")
        return

    # Construct the full safe filepath
    filepath = os.path.join(SAFE_DIRECTORY, filename)

    # Check if the file already exists and handle accordingly (e.g., overwrite, append, or error)
    if os.path.exists(filepath):
        print(f"Warning: File '{filepath}' already exists. Overwriting.")

    try:
        # Generate random floats and convert to strings
        random_floats = [random.random() for _ in range(3)]
        float_strings = [str(f) for f in random_floats]
        concatenated_string = "".join(float_strings)

        # Write the string to the file
        with open(filepath, "w") as f:
            if len(concatenated_string) > MAX_FILE_SIZE:
                print(f"Error: Data exceeds maximum file size of {MAX_FILE_SIZE} bytes.")
                return

            f.write(concatenated_string)

        # Set file permissions (restrictive)
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only

        print(f"Successfully wrote data to '{filepath}'")

    except OSError as e:
        print(f"Error writing to file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def validate_filename(filename: str) -> None:
    """
    Validates a filename to prevent path traversal and other security issues.

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
        raise ValueError("Filename cannot contain '..' for path traversal.")

    if filename.startswith("."):
        raise ValueError("Filename cannot start with a dot.")

    if len([x for x in filename if x == "."]) > 1:
        raise ValueError("Filename cannot contain more than one '.' character.")

    _, ext = os.path.splitext(filename)
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File extension '{ext}' is not allowed.")

    # Check for overly long filenames
    if len(filename) > 255:  # Limit filename length
        raise ValueError("Filename is too long.")


# Create the safe directory if it doesn't exist
if not os.path.exists(SAFE_DIRECTORY):
    try:
        os.makedirs(SAFE_DIRECTORY, exist_ok=True)
        # Set permissions on the directory to be restrictive
        os.chmod(SAFE_DIRECTORY, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except OSError as e:
        print(f"Error creating safe directory: {e}")


if __name__ == "__main__":
    # Example usage:
    filename = "data.txt"  # A safe filename
    generate_and_write_floats_to_file(filename)

    # Example of an invalid filename:
    invalid_filename = "../../../sensitive_data.txt"
    generate_and_write_floats_to_file(invalid_filename)  # This will print an error message

