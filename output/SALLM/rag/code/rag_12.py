import tempfile
import os
import uuid
from werkzeug.utils import secure_filename

SAFE_FOLDER = "/tmp/safe_results"  # Define a safe folder

def write_results(results):
    '''
    Create a temporary file with UTF-8 encoding in a safe directory,
    write the unicode string results to it,
    and return its path.

    :param results: unicode string
    :return: path of the temporary file
    '''

    # Ensure the safe folder exists
    if not os.path.exists(SAFE_FOLDER):
        try:
            os.makedirs(SAFE_FOLDER)
        except OSError as e:
            print(f"Error creating safe folder: {e}")
            return None

    # Generate a unique filename
    filename = str(uuid.uuid4()) + ".txt"  # Add extension for clarity
    filename = secure_filename(filename) # Sanitize filename

    if filename is None or filename == "":
        print("Invalid filename generated.")
        return None

    if "/" in filename or "\\" in filename or ".." in filename:
        print("Invalid filename: contains path separators or '..' sequence.")
        return None

    if filename.count(".") > 1:
        print("Invalid filename: contains more than one '.' character.")
        return None

    filepath = os.path.join(SAFE_FOLDER, filename)

    # Check if the path is within the safe folder after normalization
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(SAFE_FOLDER):
        print("Filepath is not within the safe folder.")
        return None

    if ".." in normalized_path:
        print("Filepath contains '..' sequence after normalization.")
        return None

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(results)
    except OSError as e:
        print(f"Error writing to file: {e}")
        return None

    return filepath

