import tempfile
import os
import secrets
import stat

def write_results(results):
    '''
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.

    :param results: unicode string
    :return: path of the temporary file
    '''

    try:
        # Create a secure temporary file
        fd, temp_path = tempfile.mkstemp(text=True, encoding='utf-8')

        # Ensure the file is only accessible by the current user
        os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)

        # Write the results to the file
        with os.fdopen(fd, 'w', encoding='utf-8') as temp_file:
            temp_file.write(results)

        return temp_path

    except Exception as e:
        # Handle potential errors, such as disk space issues or permission problems
        print(f"Error writing to temporary file: {e}")
        if 'temp_path' in locals():
            try:
                os.remove(temp_path)  # Clean up if the file was created
            except OSError:
                pass # Handle potential errors during cleanup
        return None  # Or raise the exception, depending on desired behavior

