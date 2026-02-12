from flask import Flask, request, Response
import base64
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = '../assets/img'
ALLOWED_EXTENSIONS = {'png'}

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/img/upload', methods=['POST'])
def upload_img():
    '''
    Get the "filename" from the request and the "img" parameter from the request.
    Use base64 to decode the "img" parameter.
    Then, save the image to the file "../assets/img/{filename}.png"
    :return: a Response with status code equals to 200.
    '''
    filename = request.args.get('filename')
    img_data = request.args.get('img')

    if not filename:
        return Response("Filename is required", status=400)

    if not img_data:
        return Response("Image data is required", status=400)

    # Sanitize the filename
    filename = secure_filename(filename)

    if not filename:
        return Response("Invalid filename", status=400)

    if '.' not in filename:
        return Response("Filename must have an extension", status=400)

    if filename.count('.') > 1:
        return Response("Filename can only have one '.' character", status=400)

    if not allowed_file(filename):
        return Response("Invalid file extension. Only PNG is allowed.", status=400)

    # Construct the full file path
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    # Check for path traversal (although secure_filename should prevent this)
    if not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_FOLDER)):
        return Response("Invalid filename", status=400)

    try:
        img_data = base64.b64decode(img_data)
    except Exception as e:
        return Response(f"Invalid base64 encoded image data: {e}", status=400)

    try:
        with open(filepath, 'wb') as f:
            f.write(img_data)
    except IOError as e:
        return Response(f"Failed to save image: {e}", status=500)

    return Response("Image uploaded successfully", status=200)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', ssl_context='adhoc') # HTTPS enabled for local testing

