import random
import os
from werkzeug.utils import secure_filename

# Define a safe directory to store the file
SAFE_DIRECTORY = "safe_files"
MAX_FILE_SIZE = 1024  # Maximum file size in bytes

def generate_and_write_data(filename):
    """
    Generates 3 random floats, converts them to strings, concatenates them,
    and writes the string to a file within a safe directory.

    Args:
        filename (str): The desired filename (without path).  Must be a safe filename.
    """

    # Validate filename using werkzeug.secure_filename
    validated_filename = secure_filename(filename)

    if validated_filename != filename:
        raise ValueError("Invalid filename.  Filename must contain only safe characters.")

    if "." not in filename:
        raise ValueError("Invalid filename. Filename must contain an extension.")

    if filename.count(".") > 1:
        raise ValueError("Invalid filename. Filename must contain only one '.' character.")

    if "/" in filename or "\\" in filename:
        raise ValueError("Invalid filename. Filename must not contain path separators.")

    if filename == "." or filename == "..":
        raise ValueError("Invalid filename. Filename must not be '.' or '..'")

    # Create the safe directory if it doesn't exist
    if not os.path.exists(SAFE_DIRECTORY):
        os.makedirs(SAFE_DIRECTORY)

    # Construct the full file path
    filepath = os.path.join(SAFE_DIRECTORY, validated_filename)

    # Generate random floats and convert to strings
    random_floats = [random.random() for _ in range(3)]
    string_floats = [str(f) for f in random_floats]
    concatenated_string = "".join(string_floats)

    # Write the string to the file
    try:
        with open(filepath, "w") as f:
            f.write(concatenated_string)
            # Check file size to prevent unlimited growth
            if os.path.getsize(filepath) > MAX_FILE_SIZE:
                os.remove(filepath)
                raise ValueError(f"File size exceeds maximum allowed size of {MAX_FILE_SIZE} bytes.")

    except OSError as e:
        raise OSError(f"Error writing to file: {e}")


if __name__ == "__main__":
    try:
        generate_and_write_data("my_data.txt")  # Example usage with a safe filename
        print("Data written to file successfully.")

        # Example of an invalid filename (demonstrates security)
        # generate_and_write_data("../../../evil.txt")  # This will raise a ValueError
    except ValueError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"OS Error: {e}")

