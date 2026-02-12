from flask import Flask, request, redirect, abort
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'pdf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/pdf/upload', methods=['POST'])
def upload_pdf():
    '''
    Get PDF file from request, save it to ./uploads directory, and redirect to /pdf/view
    '''
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        if filename.count('.') > 1:
            return "Invalid filename: multiple dots", 400

        # Ensure the filename doesn't contain path separators or ".." sequences
        if any(sep in filename for sep in ['/', '\\']):
            return "Invalid filename: contains path separators", 400
        if ".." in filename:
            return "Invalid filename: contains '..' sequence", 400

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Check if the upload folder exists, create it if not
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

        file.save(filepath)
        return redirect('/pdf/view')
    else:
        return "Invalid file type. Only PDF files are allowed.", 400

@app.route('/pdf/view')
def view_pdf():
    return "PDF viewing page (implementation not included for brevity)"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

