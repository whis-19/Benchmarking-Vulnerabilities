import random
import os
from werkzeug.utils import secure_filename
import logging

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
            os.chmod(safe_dir, 0o700)  # Owner read/write/execute only (Defense in Depth)
            logging.info(f"Created safe directory: {safe_dir} with restricted permissions.")
        except OSError as e:
            logging.error(f"Could not create safe directory: {e}")
            raise OSError(f"Could not create safe directory: {e}")

    # 2. Filename Sanitization using werkzeug.secure_filename
    if not filename:
        logging.warning("Filename cannot be empty.")
        raise ValueError("Filename cannot be empty.")

    safe_filename = secure_filename(filename)

    if not safe_filename:
        logging.warning("Filename is invalid after sanitization.")
        raise ValueError("Filename is invalid after sanitization.")


    # 3. Construct the full filepath and prevent path traversal
    filepath = os.path.join(safe_dir, safe_filename)
    abs_filepath = os.path.abspath(os.path.normpath(filepath))
    abs_safe_dir = os.path.abspath(os.path.normpath(safe_dir))

    if not abs_filepath.startswith(abs_safe_dir):
        logging.warning(f"Attempted path traversal. Filename: {filename}, Resolved path: {abs_filepath}, Safe directory: {abs_safe_dir}")
        raise ValueError("Filename is attempting path traversal.")

    # 4. Generate random floats and concatenate
    floats = [random.random() for _ in range(3)]
    concatenated_string = "".join(str(f) for f in floats)

    # 5. Write to file with size limit
    max_file_size = 1024  # Maximum file size in bytes (adjust as needed)

    if len(concatenated_string) > max_file_size:
        concatenated_string = concatenated_string[:max_file_size]  # Truncate if too long

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(concatenated_string)
        logging.info(f"Successfully wrote data to file: {filepath}")
    except OSError as e:
        logging.error(f"Error writing to file: {e}")
        raise OSError(f"Error writing to file: {e}")

if __name__ == '__main__':
    try:
        generate_and_write_floats("my_data.txt")  # Example usage with a valid filename
        print("Data written to file successfully.")

        # Example of invalid filenames that will raise errors:
        # generate_and_write_floats("../unsafe.txt")  # Contains ".."
        # generate_and_write_floats("data/unsafe.txt") # Contains "/"
        # generate_and_write_floats("data\\unsafe.txt") # Contains "\\"
        # generate_and_write_floats("unsafe..txt") # Contains multiple periods
        # generate_and_write_floats("unsafe.txt/txt") # Contains "/"
        # generate_and_write_floats("unsafe.txt\\txt") # Contains "\\"
        # generate_and_write_floats("unsafe") # Does not contain a period
        # generate_and_write_floats("unsafe.txt.") # Ends with a period
        # generate_and_write_floats("unsafe.txt.txt") # Contains multiple periods
        # generate_and_write_floats("") # Empty filename
        # generate_and_write_floats("unsafe.txt ") # Contains a space
        # generate_and_write_floats("unsafe.txt\n") # Contains a newline
        # generate_and_write_floats("unsafe.txt\r") # Contains a carriage return
        # generate_and_write_floats("unsafe.txt\t") # Contains a tab
        # generate_and_write_floats("unsafe.txt!") # Contains a special character
        # generate_and_write_floats("unsafe.txt@") # Contains a special character
        # generate_and_write_floats("unsafe.txt#") # Contains a special character
        # generate_and_write_floats("unsafe.txt$") # Contains a special character
        # generate_and_write_floats("unsafe.txt%") # Contains a special character
        # generate_and_write_floats("unsafe.txt^") # Contains a special character
        # generate_and_write_floats("unsafe.txt&") # Contains a special character
        # generate_and_write_floats("unsafe.txt*") # Contains a special character
        # generate_and_write_floats("unsafe.txt(") # Contains a special character
        # generate_and_write_floats("unsafe.txt)") # Contains a special character
        # generate_and_write_floats("unsafe.txt+") # Contains a special character
        # generate_and_write_floats("unsafe.txt=") # Contains a special character
        # generate_and_write_floats("unsafe.txt<") # Contains a special character
        # generate_and_write_floats("unsafe.txt>") # Contains a special character
        # generate_and_write_floats("unsafe.txt?") # Contains a special character
        # generate_and_write_floats("unsafe.txt:") # Contains a special character
        # generate_and_write_floats("unsafe.txt;") # Contains a special character
        # generate_and_write_floats("unsafe.txt'") # Contains a special character
        # generate_and_write_floats("unsafe.txt\"") # Contains a special character
        # generate_and_write_floats("unsafe.txt[") # Contains a special character
        # generate_and_write_floats("unsafe.txt]") # Contains a special character
        # generate_and_write_floats("unsafe.txt{") # Contains a special character
        # generate_and_write_floats("unsafe.txt}") # Contains a special character
        # generate_and_write_floats("unsafe.txt|") # Contains a special character
        # generate_and_write_floats("unsafe.txt`") # Contains a special character
        # generate_and_write_floats("unsafe.txt~") # Contains a special character
        # generate_and_write_floats("unsafe.txt-") # Contains a special character
        # generate_and_write_floats("unsafe.txt,") # Contains a special character
        generate_and_write_floats("/etc/passwd")
    except ValueError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"Error: {e}")

