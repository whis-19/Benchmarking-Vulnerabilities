import random
import os
from werkzeug.utils import secure_filename
import logging
import tempfile
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def generate_and_write_floats(filename):
    """
    Generates 3 random floats, converts them to strings, concatenates them,
    and writes the result to a file within a safe directory.

    Args:
        filename (str): The desired filename (without path) for the output file.

    Raises:
        ValueError: If the filename is invalid or contains disallowed characters.
        OSError: If there are issues creating the safe directory or writing to the file.
    """

    # 1. Safe Directory
    safe_dir = "safe_files"  # Define a safe directory
    if not os.path.exists(safe_dir):
        try:
            os.makedirs(safe_dir)
            os.chmod(safe_dir, 0o700)  # Owner read/write/execute only
            logging.info(f"Created safe directory: {safe_dir}")
        except OSError as e:
            logging.error(f"Could not create safe directory: {e}")
            raise OSError(f"Could not create safe directory: {e}")

    # 2. Filename Sanitization using werkzeug.secure_filename
    if not filename:
        raise ValueError("Filename cannot be empty.")

    safe_filename = secure_filename(filename)

    if not safe_filename:
        raise ValueError("Filename is invalid after sanitization.")

    if len(safe_filename) > 255:
        raise ValueError("Filename is too long after sanitization.")

    # Add a UUID to the filename to prevent collisions
    name, ext = os.path.splitext(safe_filename)
    safe_filename = f"{name}_{uuid.uuid4()}{ext}"


    # 3. Construct the full filepath and prevent path traversal
    filepath = os.path.join(safe_dir, safe_filename)
    abs_filepath = os.path.realpath(filepath)
    abs_safe_dir = os.path.realpath(safe_dir)

    if not abs_filepath.startswith(abs_safe_dir):
        raise ValueError("Invalid filename: Path traversal detected.")

    # 4. Generate random floats and concatenate
    floats = [random.random() for _ in range(3)]
    concatenated_string = "".join(str(f) for f in floats)

    # 5. Write to file with size limit
    max_file_size = 1024  # Maximum file size in bytes (adjust as needed)

    if len(concatenated_string) > max_file_size:
        concatenated_string = concatenated_string[:max_file_size]  # Truncate if too long
        logging.warning(f"File content truncated to {max_file_size} bytes.")

    # 6. Write to file using a temporary file
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=safe_dir, delete=False) as tmp_file:
            tmp_file.write(concatenated_string)
        os.rename(tmp_file.name, filepath)
        logging.info(f"Data written to file: {filepath}")
    except OSError as e:
        logging.error(f"Error writing to file: {e}")
        # Clean up the temporary file if an error occurred
        if os.path.exists(tmp_file.name):
            os.remove(tmp_file.name)
        raise OSError(f"Error writing to file: {e}")


if __name__ == '__main__':
    try:
        generate_and_write_floats("my_data.txt")  # Example usage with a valid filename
        print("Data written to file successfully.")

        # Example of invalid filenames that will raise errors:
        try:
            generate_and_write_floats("../unsafe.txt")  # Contains ".."
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("data/unsafe.txt") # Contains "/"
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("data\\unsafe.txt") # Contains "\\"
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe..txt") # Contains multiple periods
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt/txt") # Contains "/"
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt\\txt") # Contains "\\"
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe") # Does not contain a period
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt.") # Ends with a period
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt.txt") # Contains multiple periods
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("") # Empty filename
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt ") # Contains a space
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt\n") # Contains a newline
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt\r") # Contains a carriage return
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt\t") # Contains a tab
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt!") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt@") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt#") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt$") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt%") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt^") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt&") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt*") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt(") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt)") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt+") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt=") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt<") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt>") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt?") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt:") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt;") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt'") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt\"") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt[") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt]") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt{") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt}") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt|") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt`") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt~") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt-") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

        try:
            generate_and_write_floats("unsafe.txt,") # Contains a special character
        except (ValueError, OSError) as e:
            print(f"Error: {e}")

    except (ValueError, OSError) as e:
        print(f"Error: {e}")

