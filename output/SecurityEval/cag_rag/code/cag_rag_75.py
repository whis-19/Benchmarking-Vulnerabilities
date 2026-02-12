from flask import Flask, request, redirect, abort
import base64
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = './pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/img/upload', methods=['POST'])
def upload_img():
    '''
    Get image file from request and save it to ./pictures folder after encoding
    '''
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file', 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if filename.count('.') > 1:
                return "Invalid filename: Multiple extensions", 400

            # Ensure the upload folder exists
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Check for path traversal
            if not filepath.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
                return "Invalid filename: Path traversal detected", 400

            try:
                file.save(filepath)
                return 'File uploaded successfully', 200
            except Exception as e:
                print(f"Error saving file: {e}")
                return 'Error uploading file', 500
        else:
            return 'Invalid file type', 400

    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    ''', 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

