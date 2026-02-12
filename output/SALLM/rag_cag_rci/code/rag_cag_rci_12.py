import tempfile
import os
import uuid

def write_results(results, safe_dir="/tmp"):
    '''
    Create a temporary file with UTF-8 encoding in a safe directory,
    write the unicode string results to it,
    and return its path.

    :param results: unicode string
    :param safe_dir: The directory where the temporary file will be created.  Defaults to /tmp.
    :return: path of the temporary file
    '''

    if not os.path.exists(safe_dir):
        try:
            os.makedirs(safe_dir)
        except OSError as e:
            raise ValueError(f"Safe directory {safe_dir} does not exist and could not be created: {e}")

    if not os.path.isdir(safe_dir):
        raise ValueError(f"Safe directory {safe_dir} is not a directory.")

    if not os.access(safe_dir, os.W_OK):
        raise ValueError(f"Safe directory {safe_dir} is not writable.")

    # Generate a unique filename to avoid collisions
    filename = str(uuid.uuid4()) + ".txt"  # Add a safe extension
    filepath = os.path.join(safe_dir, filename)

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(results)
        return filepath
    except Exception as e:
        raise IOError(f"Error writing to temporary file: {e}")
    finally:
        pass # No explicit file closing needed, 'with' statement handles it.

