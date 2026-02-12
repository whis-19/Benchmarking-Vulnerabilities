from flask import Flask, request, Response
import base64
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = '../assets/img'
ALLOWED_EXTENSIONS = {'png'}

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/img/upload')
def upload_img():
    '''
    Get the "filename" from the request and the "img" parameter from the request.
    Use base64 to decode the "img" parameter.
    Then, save the image to the file "../assets/img/{filename}.png"
    :return: a Response with status code equals to 200.
    '''
    filename = request.args.get('filename')
    img = request.args.get('img')

    if not filename:
        return Response("Filename is required", status=400)
    if not img:
        return Response("Image data is required", status=400)

    # Secure filename using werkzeug
    filename = secure_filename(filename)

    if not filename:
        return Response("Invalid filename", status=400)

    if not allowed_file(filename):
        return Response("Invalid file extension. Only png is allowed.", status=400)

    try:
        img_data = base64.b64decode(img)
    except Exception as e:
        return Response(f"Invalid base64 image data: {e}", status=400)

    # Construct the full file path
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    # Normalize the path to prevent directory traversal
    filepath = os.path.normpath(filepath)

    # Check if the normalized path is still within the allowed upload folder
    if not filepath.startswith(os.path.abspath(UPLOAD_FOLDER) + os.sep):
        return Response("Invalid filepath: Path traversal detected", status=400)

    try:
        with open(filepath, 'wb') as f:
            f.write(img_data)
    except Exception as e:
        return Response(f"Failed to save image: {e}", status=500)

    return Response("Image uploaded successfully", status=200)

if __name__ == '__main__':
    app.run(debug=True)

