import random
import os
from werkzeug.utils import secure_filename

# Define a safe directory to store the file
SAFE_DIRECTORY = "safe_files"
MAX_FILE_SIZE = 1024  # Maximum file size in bytes

def generate_and_write_floats(filename):
    """
    Generates 3 random floats, converts them to strings, concatenates them,
    and writes the string to a file within a safe directory.

    Args:
        filename (str): The desired filename (without path) for the output file.
                         Must be a safe filename.

    Raises:
        ValueError: If the filename is invalid or contains unsafe characters.
        OSError: If there are issues creating the safe directory or writing to the file.
    """

    # Validate the filename using werkzeug.secure_filename
    validated_filename = secure_filename(filename)

    if not validated_filename:
        raise ValueError("Invalid filename.  Filename must contain only letters, numbers, underscores, and a single period.")

    if "/" in validated_filename or "\\" in validated_filename or ".." in validated_filename:
        raise ValueError("Invalid filename.  Filename cannot contain path separators or '..' sequences.")

    if validated_filename.count(".") > 1:
        raise ValueError("Invalid filename. Filename can only contain a single '.' character.")

    # Create the safe directory if it doesn't exist
    if not os.path.exists(SAFE_DIRECTORY):
        try:
            os.makedirs(SAFE_DIRECTORY)
        except OSError as e:
            raise OSError(f"Failed to create safe directory: {e}")

    # Construct the full filepath
    filepath = os.path.join(SAFE_DIRECTORY, validated_filename)

    # Generate random floats and convert to strings
    floats = [random.random() for _ in range(3)]
    float_strings = [str(f) for f in floats]
    concatenated_string = "".join(float_strings)

    # Write the string to the file, limiting the file size
    try:
        with open(filepath, "w") as f:
            if len(concatenated_string) > MAX_FILE_SIZE:
                f.write(concatenated_string[:MAX_FILE_SIZE])  # Truncate if too large
                print(f"Warning: String truncated to {MAX_FILE_SIZE} bytes.")
            else:
                f.write(concatenated_string)
    except OSError as e:
        raise OSError(f"Failed to write to file: {e}")

if __name__ == '__main__':
    try:
        generate_and_write_floats("my_data.txt")  # Example usage with a safe filename
        print("Data written to safe_files/my_data.txt")

        # Example of an invalid filename (will raise an exception)
        # generate_and_write_floats("../unsafe_data.txt")
    except ValueError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"File error: {e}")

