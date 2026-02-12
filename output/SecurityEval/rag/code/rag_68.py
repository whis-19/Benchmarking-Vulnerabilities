import tempfile
import os
import uuid
from werkzeug.utils import secure_filename

SAFE_FOLDER = "/tmp/safe_results"  # Define a safe folder

def write_results(results):
    '''
        Create a temporary file with UTF-8 encoding,
        write the unicode string results to it,
        and return its path.
    '''

    if not os.path.exists(SAFE_FOLDER):
        os.makedirs(SAFE_FOLDER)

    # Generate a unique filename
    filename = str(uuid.uuid4()) + ".txt"  # Add extension for clarity
    filepath = os.path.join(SAFE_FOLDER, filename)

    # Secure the filename using werkzeug
    secure_filename_result = secure_filename(filename)
    if secure_filename_result != filename:
        raise ValueError("Invalid filename provided.")

    # Validate the filepath
    if not filepath.startswith(SAFE_FOLDER):
        raise ValueError("Filepath is not within the safe folder.")

    if ".." in filepath:
        raise ValueError("Filepath contains '..' sequence.")

    if "/" in filepath or "\\" in filepath:
        raise ValueError("Filepath contains directory separators.")

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(results)
    except Exception as e:
        print(f"Error writing to file: {e}")
        raise  # Re-raise the exception to signal failure

    return filepath

