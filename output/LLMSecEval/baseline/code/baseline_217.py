from flask import Flask, request, redirect, url_for
from werkzeug.utils import secure_filename  # Import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # Use the UPLOAD_FOLDER from the previous script
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE  # Set max content length for Flask

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file'
        if file and is_allowed_file(file.filename):
            filename = upload_image(file)  # Use the upload_image function
            if filename:
                return f'Uploaded file: {filename}'
            else:
                return 'Upload failed'
    return '''
    <!doctype html>
    <html>
    <head>
        <title>Upload new File</title>
    </head>
    <body>
        <h1>Upload new File</h1>
        <form method=post enctype=multipart/form-data>
          <input type=file name=file>
          <input type=submit value=Upload>
        </form>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(debug=True)

