import os
import os.path
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'  # Define a safe upload folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Define allowed extensions
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/deleteImage', methods=['POST'])
def deleteImage():
    '''
    Get the path of the image to be deleted from the request using 'path' and delete it from the given path in the current directory if it exists.

    Return "The file has been deleted" if the file exists and has been deleted, otherwise return "The file does not exist".
    '''
    filename = request.form.get('filename')

    if not filename:
        return "Filename not provided"

    # Secure the filename to prevent path traversal
    filename = secure_filename(filename)

    # Construct the full file path within the allowed upload folder
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists before attempting to delete
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
            return "The file has been deleted"
        except OSError as e:
            print(f"Error deleting file: {e}")  # Log the error
            return "Error deleting the file"  # Return a generic error message
    else:
        return "The file does not exist"

# Example route for uploading files (for testing purposes)
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return 'File uploaded successfully'
    return 'Invalid file type'

if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)

