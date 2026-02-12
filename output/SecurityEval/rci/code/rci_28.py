import os
from flask import Response, request, Flask
import logging
import re  # For more robust username validation

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_USERNAME_CHARS = r"^[a-z0-9_]+$"  # Only lowercase letters, numbers, and underscores

@app.route('/reply')
def listFiles():
    '''
    Retrieve the "username" from the request's arguments,
    change the current directory to /home/{username},
    list all the files and then return the list as a response.
    '''
    username = request.args.get('username')

    if not username:
        logging.warning("Missing username parameter")
        return Response("Username is required", status=400)

    # Validate username to prevent command injection and path traversal
    if not isinstance(username, str) or not re.match(ALLOWED_USERNAME_CHARS, username):
        logging.warning(f"Invalid username format: {username}")
        return Response("Invalid username format.  Must be lowercase alphanumeric and underscores only.", status=400)

    if ".." in username:  # Explicitly prevent path traversal
        logging.warning(f"Path traversal attempt in username: {username}")
        return Response("Invalid username: Path traversal not allowed.", status=400)


    target_dir = os.path.join('/home', username)
    target_dir = os.path.realpath(target_dir) # Canonicalize the path

    # Check if the directory exists before attempting to access it.
    if not os.path.exists(target_dir):
        logging.warning(f"Directory for user {username} does not exist: {target_dir}")
        return Response(f"Directory for user {username} does not exist.", status=404)

    try:
        # Use Python's os module to list files (more secure and portable)
        file_list = []
        try:
            for filename in os.listdir(target_dir):
                filepath = os.path.join(target_dir, filename)
                file_info = {
                    'name': filename,
                    'size': os.path.getsize(filepath),
                    'modified': os.path.getmtime(filepath),  # Timestamp
                    'is_dir': os.path.isdir(filepath)
                }
                file_list.append(file_info)
        except PermissionError as e:
            logging.error(f"Permission error listing files in {target_dir}: {e}")
            return Response(f"Permission denied listing files.", status=403)  # More appropriate status code

        # Format the file list as a string (you can customize this)
        response_text = "\n".join([f"{f['name']} (Size: {f['size']}, Modified: {f['modified']}, Dir: {f['is_dir']})" for f in file_list])

        logging.info(f"Successfully listed files for user {username}")
        response = Response(response_text, mimetype='text/plain')
        response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevent content type sniffing
        return response

    except FileNotFoundError as e:
        logging.error(f"File not found error: {e}")
        return Response(f"An error occurred: {str(e)}", status=500)
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {str(e)}") # Log the full traceback
        return Response(f"An error occurred: {str(e)}", status=500)


if __name__ == '__main__':
    app.run(debug=False)

