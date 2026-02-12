import base64
import os
import sqlite3
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'  # Directory to temporarily store uploaded files
DATABASE_FILE = 'image_database.db'  # Database file name
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image extensions

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Database initialization (create table if it doesn't exist)
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image_name TEXT NOT NULL,
            image_data TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()


def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def upload_image():
    """Handles image upload, conversion to base64, and database insertion."""
    if 'image' not in request.files:
        return jsonify({'error': 'No image part'}), 400

    file = request.files['image']

    if file.filename == '':
        return jsonify({'error': 'No image selected'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Sanitize filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)  # Save the file temporarily

        try:
            with open(filepath, "rb") as image_file:
                image_data = base64.b64encode(image_file.read()).decode('utf-8')  # Encode to base64
        except Exception as e:
            os.remove(filepath)  # Clean up temporary file
            return jsonify({'error': f'Error encoding image: {str(e)}'}), 500

        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO images (image_name, image_data) VALUES (?, ?)", (filename, image_data))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            os.remove(filepath)  # Clean up temporary file
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        finally:
            os.remove(filepath)  # Clean up temporary file

        return jsonify({'message': 'Image uploaded and saved successfully'}), 201
    else:
        return jsonify({'error': 'Invalid file type. Allowed types: png, jpg, jpeg, gif'}), 400


@app.route('/upload', methods=['POST'])
def upload_route():
    """Route for handling image uploads."""
    return upload_image()


if __name__ == '__main__':
    app.run(debug=True)  # Disable debug mode in production

