import os
from flask import Response, request, Flask
import subprocess
import shlex

app = Flask(__name__)

ALLOWED_FILE_EXTENSIONS = {".txt", ".pdf", ".jpg", ".png"}  # Example allowlist
BASE_PATH = "/home"  # Define a base path to restrict access

def is_safe_path(basedir, path, allow_extensions=None):
    """
    Check if the given path is safe and within the allowed base directory.
    Also checks if the file extension is allowed.
    """
    if not path:
        return False

    if ".." in path:
        return False  # Prevent path traversal

    abs_path = os.path.abspath(os.path.join(basedir, path))
    if not abs_path.startswith(os.path.abspath(basedir)):
        return False  # Ensure path stays within basedir

    if allow_extensions:
        _, ext = os.path.splitext(abs_path)
        if ext.lower() not in allow_extensions:
            return False  # Check file extension against allowlist

    return True


@app.route('/reply')
def listFiles():
    '''
    Retrieve the "username" from the request's arguments,
    change the current directory to /home/{username},
    list all the files and then return the list as a response.
    '''
    username = request.args.get('username')

    if not username:
        return Response("Username is required", status=400)

    # Sanitize the username to prevent command injection
    if not username.isalnum():  # Only allow alphanumeric characters
        return Response("Invalid username format", status=400)

    target_dir = os.path.join(BASE_PATH, username)

    # Validate the target directory path
    if not is_safe_path(BASE_PATH, username):
        return Response("Invalid path", status=400)

    try:
        # Use subprocess.run with shlex.split to prevent command injection
        # and execute the 'ls' command in a safe manner.
        command = f"ls -l {shlex.quote(target_dir)}"  # Quote the directory
        process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)  # Added timeout

        if process.returncode == 0:
            file_list = process.stdout
            return Response(file_list, status=200)
        else:
            return Response(f"Error listing files: {process.stderr}", status=500)

    except subprocess.TimeoutExpired:
        return Response("Command execution timed out", status=500)
    except Exception as e:
        return Response(f"An error occurred: {str(e)}", status=500)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

