from flask import Flask, request, abort, Response
import lxml.etree
import os
from defusedxml import ElementTree as ET  # Import defusedxml for safer XML parsing
from werkzeug.utils import secure_filename  # Import secure_filename for safer filename handling

app = Flask(__name__)

# Configure allowed file extensions and upload folder
UPLOAD_FOLDER = 'uploads'  # Create this folder in your project directory
ALLOWED_EXTENSIONS = {'xml'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create the upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def checkPassword(userid, password):
    """
    Placeholder function for password checking.  **IMPORTANT:**  Replace this with a secure authentication mechanism.
    This example uses a hardcoded user/password for demonstration purposes ONLY.  DO NOT use this in production.

    Args:
        userid: The user ID.
        password: The password.

    Returns:
        True if the user ID and password are correct, False otherwise.
    """
    # **INSECURE EXAMPLE - REPLACE WITH SECURE AUTHENTICATION**
    if userid == "testuser" and password == "testpassword":
        return True
    else:
        return False


def allowed_file(filename):
    """
    Checks if the file extension is allowed.

    Args:
        filename: The name of the file.

    Returns:
        True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=['POST'])
def upload():
    """
    Handles the XML file upload.  Performs authentication and XML parsing with security considerations.
    """
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Sanitize filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)  # Save the file to the upload folder

        try:
            # Parse the XML file using defusedxml to prevent XML vulnerabilities
            tree = ET.parse(filepath)
            root = tree.getroot()

            # Extract userid and password from the XML (example structure)
            userid = root.findtext("userid")
            password = root.findtext("password")

            if userid is None or password is None:
                os.remove(filepath)  # Clean up the uploaded file
                return "Missing userid or password in XML", 400

            # Authenticate the user
            if checkPassword(userid, password):
                # Process the XML data (example: print the root tag)
                print(f"XML Root Tag: {root.tag}")

                # **IMPORTANT:**  Implement your actual XML processing logic here.
                # Be very careful when processing XML data.  Validate the data
                # against a schema to ensure it conforms to the expected structure
                # and data types.  Sanitize any data before using it in further
                # operations (e.g., database queries).

                os.remove(filepath)  # Clean up the uploaded file
                return "Upload successful and XML processed", 200
            else:
                os.remove(filepath)  # Clean up the uploaded file
                return "Authentication failed", 401

        except ET.ParseError as e:
            os.remove(filepath)  # Clean up the uploaded file
            return f"Invalid XML: {e}", 400
        except Exception as e:
            os.remove(filepath)  # Clean up the uploaded file
            return f"An error occurred: {e}", 500
    else:
        return "Invalid file type", 400


if __name__ == '__main__':
    app.run(debug=True)

