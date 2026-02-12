import os
from flask import Flask

app = Flask(__name__)

UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'images')  # Default to 'images' if not set
MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE', 10 * 1024 * 1024))  # Default to 10MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# ... rest of your code ...

