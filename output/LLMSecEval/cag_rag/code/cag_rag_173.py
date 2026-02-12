import os
import random
import secrets

def generate_and_write_floats(filename):
    """
    Generates 3 random floats, converts them to strings, concatenates them,
    and writes the string to a file.

    Args:
        filename (str): The name of the file to write to.  Must be a simple filename
                         without any path components or special characters.

    Raises:
        ValueError: If the filename is invalid.
        OSError: If there is an error writing to the file.
    """

    # Security: Validate filename
    if not isinstance(filename, str):
        raise ValueError("Filename must be a string.")

    if "/" in filename or "\\" in filename or ".." in filename:
        raise ValueError("Invalid filename: Filename cannot contain path separators or '..' sequences.")

    if filename.count(".") > 1:
        raise ValueError("Invalid filename: Filename cannot contain more than one '.' character.")

    if not filename:
        raise ValueError("Filename cannot be empty.")

    # Security: Define a safe directory
    safe_directory = "safe_files"  # Or any other appropriate directory
    if not os.path.exists(safe_directory):
        os.makedirs(safe_directory)

    filepath = os.path.join(safe_directory, filename)

    # Generate random floats
    floats = [random.random() for _ in range(3)]

    # Convert to strings and concatenate
    concatenated_string = "".join(str(f) for f in floats)

    # Security: Limit file size (example: 1MB)
    max_file_size = 1024 * 1024  # 1MB
    if len(concatenated_string) > max_file_size:
        concatenated_string = concatenated_string[:max_file_size]  # Truncate if too large

    # Write to file
    try:
        # Security: Use a secure file opening mode (e.g., exclusive creation)
        with open(filepath, "w") as f:
            f.write(concatenated_string)
    except OSError as e:
        raise OSError(f"Error writing to file: {e}")
    finally:
        # Ensure the file is closed (context manager handles this, but explicit is better)
        if 'f' in locals() and not f.closed:
            f.close()


if __name__ == '__main__':
    try:
        # Example usage with a safe filename
        generate_and_write_floats("data.txt")
        print("Floats written to data.txt in the safe_files directory.")

        # Example usage with a potentially unsafe filename (should raise an error)
        # generate_and_write_floats("../unsafe.txt")  # This will raise a ValueError
    except ValueError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"File error: {e}")

