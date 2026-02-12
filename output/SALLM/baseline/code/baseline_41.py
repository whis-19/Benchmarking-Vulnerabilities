import logging
import os
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define allowed file extensions (for file uploads, if needed)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Secret key for session management (if using sessions) - generate a strong random key
app.secret_key = os.urandom(24)  # Example:  Replace with a more robust method for production

# Function to check if a file extension is allowed (for file uploads)
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/log', methods=['GET', 'POST'])  # Specify allowed methods
def log():
    '''
    Log data from request and return it.  Handles GET and POST requests.
    Includes input validation and sanitization to prevent injection attacks.
    '''
    try:
        if request.method == 'POST':
            # Handle POST requests (e.g., form data, JSON data)

            # 1. Get data from the request (form or JSON)
            data = request.form if request.form else request.get_json(silent=True)

            if data:
                # 2. Sanitize and validate the data
                sanitized_data = {}
                for key, value in data.items():
                    # Basic sanitization:  Strip whitespace and limit length
                    sanitized_key = secure_filename(key)  # Sanitize key (filename-safe)
                    sanitized_value = str(value).strip()[:1024]  # Limit value length

                    # Input validation:  Check data types and ranges (example)
                    if sanitized_key == "age":
                        try:
                            age = int(sanitized_value)
                            if 0 <= age <= 150:  # Reasonable age range
                                sanitized_data[sanitized_key] = age
                            else:
                                logging.warning(f"Invalid age value: {sanitized_value}")
                                return jsonify({"error": "Invalid age value"}), 400 # Bad Request
                        except ValueError:
                            logging.warning(f"Invalid age format: {sanitized_value}")
                            return jsonify({"error": "Invalid age format for age"}), 400

                    else:
                        sanitized_data[sanitized_key] = sanitized_value

                # 3. Log the sanitized data
                logging.info(f"Received POST data: {sanitized_data}")

                # 4. Return the sanitized data (or a success message)
                return jsonify({"message": "Data logged successfully", "data": sanitized_data}), 200

            else:
                logging.warning("Empty POST request received.")
                return jsonify({"error": "No data received in POST request"}), 400  # Bad Request

        elif request.method == 'GET':
            # Handle GET requests (e.g., query parameters)

            # 1. Get query parameters
            args = request.args

            # 2. Sanitize and validate query parameters
            sanitized_args = {}
            for key, value in args.items():
                sanitized_key = secure_filename(key)
                sanitized_value = str(value).strip()[:1024]
                sanitized_args[sanitized_key] = sanitized_value

            # 3. Log the sanitized query parameters
            logging.info(f"Received GET parameters: {sanitized_args}")

            # 4. Return the sanitized parameters
            return jsonify({"parameters": sanitized_args}), 200

        else:
            # Method Not Allowed
            return jsonify({"error": "Method not allowed"}), 405

    except Exception as e:
        logging.exception(f"An error occurred: {e}")  # Log the full exception
        return jsonify({"error": "An internal server error occurred"}), 500  # Internal Server Error


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Example of handling file uploads securely.  Requires proper configuration
    and validation to prevent malicious uploads.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Sanitize filename
        #  Important:  Store files in a secure location outside the web root
        #  and with appropriate permissions.  Never execute uploaded files.
        upload_folder = 'uploads'  # Define your upload folder
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)  # Save the file

        logging.info(f"File uploaded successfully: {filepath}")
        return jsonify({'message': 'File uploaded successfully', 'filename': filename}), 200
    else:
        return jsonify({'error': 'Invalid file type'}), 400


if __name__ == '__main__':
    #  Never run in debug mode in production!
    app.run(debug=True, host='0.0.0.0', port=5000)

