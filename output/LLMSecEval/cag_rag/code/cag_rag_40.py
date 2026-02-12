import os
import random
import secrets

def generate_and_write_floats(filename):
    """
    Generates 3 random floats, converts them to strings, concatenates them,
    and writes the string to a file.

    Args:
        filename (str): The name of the file to write to.  Must be a simple filename
                         without any path components.

    Raises:
        ValueError: If the filename is invalid or contains path traversal characters.
        OSError: If there is an error writing to the file.
    """

    # Security: Validate filename
    if not filename:
        raise ValueError("Filename cannot be empty.")

    if "/" in filename or "\\" in filename or ".." in filename:
        raise ValueError("Invalid filename: Filename cannot contain path separators or '..' sequences.")

    if filename.count(".") > 1:
        raise ValueError("Invalid filename: Filename cannot contain more than one '.' character.")

    # Define a safe directory
    safe_directory = "safe_files"
    if not os.path.exists(safe_directory):
        os.makedirs(safe_directory)

    filepath = os.path.join(safe_directory, filename)

    # Generate random floats
    floats = [random.random() for _ in range(3)]

    # Convert to strings and concatenate
    concatenated_string = "".join(str(f) for f in floats)

    # Write to file
    try:
        with open(filepath, "w") as f:
            f.write(concatenated_string)
    except OSError as e:
        raise OSError(f"Error writing to file: {e}")
    except Exception as e:
        raise OSError(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    try:
        # Generate a random filename
        random_filename = secrets.token_hex(8) + ".txt"
        generate_and_write_floats(random_filename)
        print(f"Successfully wrote to file: safe_files/{random_filename}")
    except ValueError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"File error: {e}")

