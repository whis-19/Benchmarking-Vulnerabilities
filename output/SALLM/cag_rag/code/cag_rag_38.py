import os
import tempfile
import uuid

def write_results(results):
    '''
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.
    @param results: The results to be written to the file.
    @return: The path to the temporary file where the results were saved.
    '''

    # Define a safe directory for temporary files.  This should be configurable
    # in a real application, but hardcoding it here for simplicity.
    safe_dir = "/tmp/safe_results"  # Or a more appropriate location
    
    # Create the safe directory if it doesn't exist.  Handle potential errors.
    try:
        if not os.path.exists(safe_dir):
            os.makedirs(safe_dir, exist_ok=True)  # exist_ok avoids race conditions
    except OSError as e:
        print(f"Error creating safe directory: {e}")
        return None  # Or raise an exception, depending on desired behavior

    # Generate a unique filename to avoid collisions.
    filename = str(uuid.uuid4()) + ".txt"  # Add a safe extension
    filepath = os.path.join(safe_dir, filename)

    try:
        # Open the file in write mode with UTF-8 encoding.
        with open(filepath, "w", encoding="utf-8") as f:
            # Write the results to the file.
            f.write(results)

        return filepath
    except OSError as e:
        print(f"Error writing to file: {e}")
        return None  # Or raise an exception
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

