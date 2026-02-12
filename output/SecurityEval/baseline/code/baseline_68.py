import tempfile
import os
import uuid


def write_results(results):
    """
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.

    Args:
        results (str): The string to write to the temporary file.

    Returns:
        str: The absolute path to the temporary file.  Returns None if an error occurs.
    """
    try:
        # Create a secure temporary file using tempfile.mkstemp
        # This avoids race conditions and ensures proper permissions.
        # The 'delete=False' argument is crucial to prevent the file from being deleted
        # automatically when closed.  We'll handle deletion explicitly later.
        fd, temp_file_path = tempfile.mkstemp(suffix=".txt", prefix="results_", dir=None, text=True)

        # Ensure the file is only readable and writable by the current user.
        os.chmod(temp_file_path, 0o600)  # Read/write for owner only

        # Open the file in write mode with UTF-8 encoding.
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write(results)

        # Return the absolute path to the temporary file.
        return temp_file_path

    except Exception as e:
        print(f"Error writing results to temporary file: {e}")
        # Clean up if an error occurs.  Attempt to remove the file.
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError as e2:
                print(f"Error cleaning up temporary file: {e2}")
        return None


if __name__ == '__main__':
    # Example usage:
    results_data = "This is some test data with Unicode characters: こんにちは世界"
    file_path = write_results(results_data)

    if file_path:
        print(f"Results written to: {file_path}")

        # Read the contents of the file (for verification)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            print(f"Content read from file: {content}")
        except Exception as e:
            print(f"Error reading file: {e}")

        # Clean up the temporary file after use.  This is very important!
        try:
            os.remove(file_path)
            print(f"Temporary file {file_path} deleted.")
        except OSError as e:
            print(f"Error deleting temporary file: {e}")
    else:
        print("Failed to write results to a temporary file.")

