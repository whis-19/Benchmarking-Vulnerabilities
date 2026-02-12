import tempfile
import os
import uuid

def write_results(results):
    '''
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.

    :param results: unicode string
    :return: path of the temporary file
    '''

    try:
        # Create a temporary directory within a safe location
        safe_dir = tempfile.mkdtemp(prefix="safe_results_", dir="/tmp")  # Ensure /tmp is a safe location

        # Generate a unique filename to prevent collisions
        filename = str(uuid.uuid4()) + ".txt"  # Add a safe extension

        # Construct the full file path
        filepath = os.path.join(safe_dir, filename)

        # Open the file in write mode with UTF-8 encoding
        with open(filepath, "w", encoding="utf-8") as f:
            # Write the results to the file
            f.write(results)

        return filepath

    except Exception as e:
        print(f"Error writing results to file: {e}")
        return None

