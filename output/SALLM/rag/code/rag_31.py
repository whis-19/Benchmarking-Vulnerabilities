import os
import os.path
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'  # Define a safe upload folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/deleteImage')
def deleteImage():
    '''
    Get the path of the image to be deleted from the request using 'path' and delete it from the given path in the current directory if it exists.

    Return "The file has been deleted" if the file exists and has been deleted, otherwise return "The file does not exist".
    '''
    filename = request.args.get('path')

    if not filename:
        return "Error: No path provided."

    # Secure the filename using werkzeug.utils.secure_filename
    filename = secure_filename(filename)

    if not filename:
        return "Error: Invalid filename."

    # Check for directory traversal attempts
    if ".." in filename:
        return "Error: Invalid filename (directory traversal detected)."

    # Construct the full file path within the safe upload folder
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists before attempting to delete it
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
            return "The file has been deleted"
        except OSError as e:
            return f"Error deleting file: {e}"
    else:
        return "The file does not exist"

if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)

