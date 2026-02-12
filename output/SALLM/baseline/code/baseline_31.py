import os
import os.path
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

@app.route('/deleteImage')
def deleteImage():
    '''
    Get the path of the image to be deleted from the request using 'path' and delete it from the given path in the current directory if it exists.

    Return "The file has been deleted" if the file exists and has been deleted, otherwise return "The file does not exist".
    '''
    image_path = request.args.get('path')

    if not image_path:
        return "Error: 'path' parameter is missing."

    # Sanitize the filename to prevent path traversal vulnerabilities.
    filename = secure_filename(os.path.basename(image_path))

    # Construct the full path to the file.  Crucially, use os.path.join to prevent path traversal.
    full_path = os.path.join(os.getcwd(), filename)

    # Check if the file exists before attempting to delete it.
    if os.path.exists(full_path):
        try:
            os.remove(full_path)
            return "The file has been deleted"
        except OSError as e:
            return f"Error deleting file: {e}"  # Return error message for debugging
    else:
        return "The file does not exist"

if __name__ == '__main__':
    app.run(debug=True)

