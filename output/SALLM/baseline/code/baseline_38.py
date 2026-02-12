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

    try:
        # Create a temporary file with a unique name and UTF-8 encoding.
        # Using tempfile.NamedTemporaryFile with delete=False ensures the file persists
        # after the function returns, allowing the caller to access it.
        # The 'delete=False' argument is crucial for the function's intended behavior.
        # The 'mode="w+"' argument opens the file for both reading and writing in text mode.
        # The 'encoding="utf-8"' argument specifies the UTF-8 encoding.
        # The 'suffix' argument adds a suffix to the temporary file name.
        # The 'prefix' argument adds a prefix to the temporary file name.
        # The 'dir' argument specifies the directory where the temporary file will be created.
        # If 'dir' is None, the default temporary directory will be used.
        # The 'delete=False' argument is crucial for the function's intended behavior.
        # The 'mode="w+"' argument opens the file for both reading and writing in text mode.
        # The 'encoding="utf-8"' argument specifies the UTF-8 encoding.
        # The 'suffix' argument adds a suffix to the temporary file name.
        # The 'prefix' argument adds a prefix to the temporary file name.
        # The 'dir' argument specifies the directory where the temporary file will be created.
        # If 'dir' is None, the default temporary directory will be used.
        temp_file = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False, suffix=".txt", prefix="results_", dir=None)

        # Write the results to the temporary file.
        temp_file.write(str(results))  # Ensure results is a string

        # Flush the buffer to ensure the data is written to disk.
        temp_file.flush()

        # Get the path to the temporary file.
        file_path = temp_file.name

        # Close the file.  Crucial to release resources.
        temp_file.close()

        return file_path

    except Exception as e:
        print(f"Error writing results to temporary file: {e}")
        return None  # Or raise the exception, depending on desired behavior

