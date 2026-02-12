import json
import os
import logging
from flask import Flask, request, send_file, session, abort
from werkzeug.utils import secure_filename
from werkzeug.security import safe_join
import base64
import binascii
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for CSRF protection
csrf = CSRFProtect(app)

# Configure basic logging
logging.basicConfig(level=logging.INFO)

# Security Headers
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '*'
})

# Whitelist approach for deserialization (if absolutely necessary)
allowed_classes = {
    'str': str,
    'int': int,
    'list': list,
    'dict': dict,
    'tuple': tuple,
    # Add other safe classes as needed, but be VERY careful!
}

UPLOAD_FOLDER = 'uploads'
DOWNLOAD_FOLDER = 'downloads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)


def sanitize_input(data, allowed_chars=None, replace_char=None):
    """Sanitizes input data by removing or replacing characters not in the allowed set."""
    if allowed_chars is None:
        # Define a default safe character set (alphanumeric and some common symbols)
        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

    if isinstance(data, str):
        if replace_char is None:
            return ''.join(c for c in data if c in allowed_chars)
        else:
            return ''.join(c if c in allowed_chars else replace_char for c in data)
    return data # Return as is if not a string


def safe_deserialize(data):
    """Safely deserializes data, prioritizing JSON and using a pickle whitelist if necessary."""
    try:
        # Attempt to decode as JSON first (safer)
        return json.loads(data)
    except json.JSONDecodeError as e:
        logging.error(f"JSONDecodeError: {e}")
    except TypeError as e:
        logging.error(f"TypeError during JSON decoding: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during JSON decoding: {e}")

    # Fallback to pickle with whitelist (USE WITH EXTREME CAUTION)
    try:
        import pickle
        obj = pickle.loads(data)
        # Check if the object is an instance of an allowed class
        if type(obj).__name__ in allowed_classes:
            return obj
        else:
            logging.warning(f"Attempted deserialization of disallowed class: {type(obj)}")
            return None  # Or raise an exception
    except Exception as e:
        logging.error(f"Pickle deserialization error: {e}", exc_info=True)
        return None


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        abort(400, "No file part")

    file = request.files['file']

    if file.filename == '':
        abort(400, "No selected file")

    filename = secure_filename(file.filename)
    if not filename:
        abort(400, "Invalid filename")

    # Sanitize the filename further
    filename = sanitize_input(filename, replace_char='_')

    filepath = safe_join(app.config['UPLOAD_FOLDER'], filename)
    if filepath is None:
        abort(400, "Invalid filepath")

    file.save(filepath)
    return 'File uploaded successfully'


@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    data = request.data
    obj = safe_deserialize(data)
    if obj is None:
        abort(400, "Invalid or unsafe data")  # Return a 400 Bad Request error
    return 'Data deserialized successfully'


@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename')
    if not filename:
        abort(400, "Filename is required")

    # Sanitize the filename
    filename = secure_filename(filename)
    if not filename:
        abort(400, "Invalid filename")

    filepath = safe_join(app.config['DOWNLOAD_FOLDER'], filename)
    if filepath is None:
        abort(400, "Invalid filepath")

    try:
        return send_file(filepath, as_attachment=True)
    except FileNotFoundError:
        abort(404, "File not found")
    except Exception as e:
        logging.error(f"Error sending file: {e}", exc_info=True)
        abort(500, "Internal server error")


@app.route('/set_cookie', methods=['POST'])
def set_cookie():
    cookie_value = request.form.get('cookie_value')
    cookie_value = sanitize_input(cookie_value)  # Sanitize the input
    session['cookie'] = cookie_value
    return 'Cookie set successfully'


@app.route('/base64decode', methods=['POST'])
def base64decode():
    encoded_data = request.form.get('data')
    if not encoded_data:
        abort(400, "No data provided")

    try:
        decoded_data = base64.b64decode(encoded_data)
        return decoded_data.decode('utf-8')
    except binascii.Error as e:
        logging.warning(f"Base64 decoding error: {e}")
        abort(400, "Invalid base64 data")
    except UnicodeDecodeError as e:
        logging.warning(f"Unicode decoding error: {e}")
        abort(400, "Invalid UTF-8 data")
    except Exception as e:
        logging.error(f"Unexpected error during base64 decoding: {e}", exc_info=True)
        abort(500, "Internal server error")


if __name__ == '__main__':
    app.run(debug=True)

