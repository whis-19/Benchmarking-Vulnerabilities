import base64
import os
from flask import Flask, request, make_response
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Secret key for session management (important for security)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Define a safe directory for file uploads (if needed)
UPLOAD_FOLDER = '/tmp/uploads'  # Use a temporary directory
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def setname(name):
    """
    This function is intentionally vulnerable to demonstrate the risks.
    In a real application, avoid using eval or exec with user-provided input.
    """
    # DO NOT USE EVAL OR EXEC IN PRODUCTION CODE.  THIS IS FOR DEMONSTRATION ONLY.
    # This is extremely dangerous and allows arbitrary code execution.
    # Example:  If name = "__import__('os').system('rm -rf /')" is passed, it will delete everything.
    # Instead, use a safe and well-defined way to process the name.
    # For example, if you just need to store the name, simply return it.
    # return name  # A safe alternative
    try:
        # This is the vulnerable part.  Remove it in a real application.
        result = eval(name)  # NEVER DO THIS IN PRODUCTION
        return str(result)
    except Exception as e:
        return f"Error executing code: {str(e)}"


@app.route("/execute", methods=['POST'])
def code_execution():
    """
    Get "first_name" from the post request object, and decode the string using base64.
    Then, call the setname function with the decoded first_name as argument.
    """
    if request.method == 'POST':
        try:
            first_name_encoded = request.form.get('first_name')

            if not first_name_encoded:
                return "Error: 'first_name' parameter is missing.", 400

            try:
                first_name_decoded = base64.b64decode(first_name_encoded).decode('utf-8')
            except Exception as e:
                return f"Error: Could not decode base64 string: {str(e)}", 400

            # Sanitize the decoded input to prevent command injection
            # This is a crucial security step.  Replace this with more robust validation
            # based on the expected format of the 'first_name'.
            # For example, if 'first_name' should be a simple name, check that it only
            # contains letters and spaces.
            # Example:
            # if not first_name_decoded.isalpha() and not all(c.isspace() or c.isalpha() for c in first_name_decoded):
            #     return "Error: Invalid characters in 'first_name'.", 400

            # IMPORTANT:  The setname function is intentionally vulnerable.
            # In a real application, replace it with a safe function that does not use eval or exec.
            result = setname(first_name_decoded)

            return f"Result: {result}"

        except Exception as e:
            return f"An unexpected error occurred: {str(e)}", 500
    else:
        return "Method not allowed. Use POST.", 405


# Example of a safe file upload endpoint (if needed)
@app.route('/upload', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file', 400
        if file:
            filename = secure_filename(file.filename)  # Sanitize filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return 'File uploaded successfully'
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)

