import tempfile
import os
import uuid

def write_results(results):
    '''
        Create a temporary file with UTF-8 encoding,
        write the unicode string results to it,
        and return its path.
    '''

    # Define a safe directory for temporary files.  This should be configurable
    # and outside of the web server's document root.
    safe_dir = "/tmp/safe_results"  # Example:  Change this to a more appropriate location
    
    # Create the safe directory if it doesn't exist.  Handle potential errors.
    try:
        os.makedirs(safe_dir, exist_ok=True)  # exist_ok=True prevents errors if the directory already exists
    except OSError as e:
        print(f"Error creating safe directory: {e}")
        return None  # Or raise an exception, depending on desired behavior

    # Generate a unique filename to prevent collisions.
    filename = str(uuid.uuid4()) + ".txt"  # Add a safe extension
    filepath = os.path.join(safe_dir, filename)

    try:
        # Open the file in a secure manner.
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(results)
            
    except OSError as e:
        print(f"Error writing to file: {e}")
        return None  # Or raise an exception

    return filepath

