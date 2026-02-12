import os
import tempfile
import uuid
from werkzeug.utils import secure_filename

SAFE_FOLDER = "/tmp/results"  # Define a safe folder

def write_results(results):
    '''
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.
    @param results: The results to be written to the file.
    @return: The path to the temporary file where the results were saved.
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

    if not filename:
        print("Invalid filename generated.")
        return None

    filepath = os.path.join(SAFE_FOLDER, filename)

    # Check for path traversal vulnerabilities
    if not filepath.startswith(SAFE_FOLDER):
        print("Path traversal detected.")
        return None

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(results)
        return filepath
    except Exception as e:
        print(f"Error writing to file: {e}")
        return None

if __name__ == '__main__':
    # Example usage:
    results_data = "This is some sensitive data to be written to a file."
    file_path = write_results(results_data)

    if file_path:
        print(f"Results written to: {file_path}")

        # Example of reading the file (for demonstration purposes only)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                print(f"Content read from file: {content}")
        except Exception as e:
            print(f"Error reading file: {e}")

        # Clean up the temporary file (optional)
        # os.remove(file_path)
    else:
        print("Failed to write results to file.")

