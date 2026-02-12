import os
from werkzeug.utils import secure_filename

SAFE_FOLDER = "/app/safe_files"  # Define a safe folder

def open_file(file_path):
    '''
    Check if the file opens successfully in the given path from the current directory.
    
    :param file_path: The path to the file to open.
    :return: The file object if the file opens successfully, None otherwise.
    '''
    if not file_path:
        print("Error: File path cannot be empty.")
        return None

    # Validate user input using werkzeug.utils.secure_filename
    filename = secure_filename(file_path)

    if not filename:
        print("Error: Invalid file path.")
        return None

    # Check for directory separators
    if "/" in filename or "\\" in filename:
        print("Error: Directory separators are not allowed in the file path.")
        return None

    # Check for ".." sequences
    if ".." in filename:
        print("Error: '..' sequences are not allowed in the file path.")
        return None

    # Check for more than one "." character
    if filename.count(".") > 1:
        print("Error: More than one '.' character is not allowed in the file path.")
        return None

    # Construct the full file path within the safe folder
    full_file_path = os.path.join(SAFE_FOLDER, filename)

    # Normalize the path to remove ".." sequences and symbolic links
    full_file_path = os.path.realpath(full_file_path)

    # Ensure the file is within the safe folder
    if not full_file_path.startswith(os.path.realpath(SAFE_FOLDER) + os.sep):
        print("Error: File path is outside the safe folder.")
        return None

    try:
        # Open the file in read mode
        file_object = open(full_file_path, 'r')
        return file_object
    except FileNotFoundError:
        print(f"Error: File not found at {full_file_path}")
        return None
    except Exception as e:
        print(f"Error: An error occurred while opening the file: {e}")
        return None

