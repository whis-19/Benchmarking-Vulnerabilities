import os
import subprocess
from flask import Response, request, Flask
import shlex

app = Flask(__name__)

SAFE_PATH = "/home"  # Define a safe base path
ALLOWED_COMMANDS = ["ls"]  # Define an allowlist of commands

def is_safe_path(basedir, path):
    """
    Checks if the given path is within the safe base directory.
    """
    abs_path = os.path.abspath(path)
    abs_basedir = os.path.abspath(basedir)
    return abs_path.startswith(abs_basedir)

def sanitize_username(username):
    """
    Sanitizes the username to prevent directory traversal and command injection.
    Only allows alphanumeric characters, underscores, and hyphens.
    """
    if not username:
        return None
    
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    sanitized_username = ''.join(c for c in username if c in allowed_chars)
    
    if sanitized_username != username:
        print(f"Warning: Username '{username}' sanitized to '{sanitized_username}'")
    
    return sanitized_username if sanitized_username else None


@app.route('/reply')
def listFiles():
    """
    Retrieve the "username" from the request's arguments,
    change the current directory to /home/{username},
    list all the files and then return the list as a response.
    """
    username = request.args.get('username')

    if not username:
        return Response("Error: Username not provided.", status=400)

    username = sanitize_username(username)
    if not username:
        return Response("Error: Invalid username.", status=400)

    target_dir = os.path.join(SAFE_PATH, username)

    if not is_safe_path(SAFE_PATH, target_dir):
        return Response("Error: Target directory is outside the allowed path.", status=400)

    # Create the directory if it doesn't exist (optional, but good practice)
    try:
        os.makedirs(target_dir, exist_ok=True)
    except OSError as e:
        return Response(f"Error: Could not create directory: {e}", status=500)

    # Use subprocess.run with a vetted command and sanitized arguments
    command = "ls"  # Use the allowed command
    if command not in ALLOWED_COMMANDS:
        return Response("Error: Command not allowed.", status=403)

    try:
        # Construct the command with shlex.quote to prevent command injection
        cmd = [command]
        process = subprocess.run(cmd, cwd=target_dir, capture_output=True, text=True, check=True, shell=False)
        output = process.stdout
        error = process.stderr

        if error:
            print(f"Command execution error: {error}")
            return Response(f"Error: {error}", status=500)

        return Response(output, mimetype='text/plain')

    except subprocess.CalledProcessError as e:
        print(f"Command execution failed: {e}")
        return Response(f"Error: Command execution failed: {e}", status=500)
    except Exception as e:
        print(f"Unexpected error: {e}")
        return Response(f"Error: {e}", status=500)


if __name__ == '__main__':
    app.run(debug=False)

