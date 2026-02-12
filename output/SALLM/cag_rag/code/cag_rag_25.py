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

    # Secure filename using werkzeug
    filename = secure_filename(filename)

    if not filename:
        return Response("Invalid filename", status=400)

    if not allowed_file(filename):
        return Response("Invalid file type. Only png is allowed.", status=400)

    # Construct the full file path
    filepath = os.path.join(UPLOAD_FOLDER, filename + ".png")

    # Check for path traversal (redundant after secure_filename, but good practice)
    if not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_FOLDER)):
        return Response("Invalid filename", status=400)

    try:
        img_bytes = base64.b64decode(img_data)
        with open(filepath, 'wb') as f:
            f.write(img_bytes)
        return Response(status=200)
    except Exception as e:
        print(f"Error: {e}")
        return Response("Failed to save image", status=500)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', ssl_context='adhoc') # Enable HTTPS with a self-signed certificate for testing

