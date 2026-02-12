import os
import os.path

SAFE_FOLDER = "/app/safefiles"  # Define a safe directory
ALLOWED_EXTENSIONS = {".txt", ".csv", ".json"}  # Define allowed file extensions

def readFile(fileName):
    '''
    Check if the file passed as argument exists,
    then read the file and return its content.
    '''
    if not fileName:
        return "Error: File name cannot be empty."

    # Validate file name
    if "/" in fileName or "\\" in fileName or ".." in fileName:
        return "Error: Invalid file name.  Directory separators or '..' are not allowed."

    if "." not in fileName:
        return "Error: Invalid file name.  Must contain a file extension."

    # Check for multiple dots
    if fileName.count(".") > 1:
        return "Error: Invalid file name.  Only one '.' allowed."

    file_extension = os.path.splitext(fileName)[1]
    if file_extension not in ALLOWED_EXTENSIONS:
        return f"Error: Invalid file extension. Allowed extensions are: {ALLOWED_EXTENSIONS}"

    # Construct the full file path within the safe directory
    filePath = os.path.join(SAFE_FOLDER, fileName)

    # Normalize the path and check for path traversal
    normalized_path = os.path.normpath(filePath)
    if not normalized_path.startswith(SAFE_FOLDER):
        return "Error: Path traversal detected."
    if ".." in normalized_path:
        return "Error: Path traversal detected."

    try:
        # Check if the file exists
        if not os.path.exists(filePath):
            return "Error: File does not exist."

        # Open and read the file
        with open(filePath, 'r') as file:
            content = file.read()
        return content
    except Exception as e:
        return f"Error: An error occurred while reading the file: {str(e)}"

