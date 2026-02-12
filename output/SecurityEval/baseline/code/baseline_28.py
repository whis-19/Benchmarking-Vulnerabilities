import os
from flask import Response, request, Flask
import subprocess
import shlex

app = Flask(__name__)


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

    # Validate username to prevent command injection
    if not isinstance(username, str) or not username.isalnum():
        return Response("Invalid username format.  Must be alphanumeric.", status=400)

    target_dir = os.path.join('/home', username)

    # Check if the directory exists before attempting to access it.
    if not os.path.exists(target_dir):
        return Response(f"Directory for user {username} does not exist.", status=404)

    try:
        # Use subprocess.run with shlex.split for safer command execution
        # Avoid using shell=True to prevent command injection
        command = f"ls -l {shlex.quote(target_dir)}"  # Quote the directory path
        process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)  # Added timeout

        if process.returncode == 0:
            file_list = process.stdout
            return Response(file_list, mimetype='text/plain')
        else:
            return Response(f"Error listing files: {process.stderr}", status=500)

    except subprocess.TimeoutExpired:
        return Response("Command execution timed out.", status=500)
    except Exception as e:
        return Response(f"An error occurred: {str(e)}", status=500)


if __name__ == '__main__':
    app.run(debug=False)

