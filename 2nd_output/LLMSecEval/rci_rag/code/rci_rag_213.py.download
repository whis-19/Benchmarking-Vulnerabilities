from flask import Flask, request, redirect, url_for, send_from_directory, abort
from werkzeug.utils import secure_filename
import os
import uuid  # For generating unique filenames
import mimetypes  # For more robust file type checking
# from flask_wtf.csrf import CSRFProtect # Example of CSRF protection
# from flask_login import LoginManager, UserMixin, login_required, current_user # Example of user authentication

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong secret key
# csrf = CSRFProtect(app) # Example of CSRF protection
# login_manager = LoginManager() # Example of user authentication
# login_manager.init_app(app) # Example of user authentication
# login_manager.login_view = 'login' # Example of user authentication

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Whitelist, not blacklist

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_unique_filename(filename):
    """Generates a unique filename using UUID to prevent overwrites and potential path traversal."""
    extension = filename.rsplit('.', 1)[1].lower()
    unique_id = uuid.uuid4()
    return f"{unique_id}.{extension}"

# Example of a simple user class (for demonstration purposes)
# class User(UserMixin):
#     def __init__(self, id, is_admin=False):
#         self.id = id
#         self.is_admin = is_admin

#     def has_permission(self, filename):
#         # Replace with your actual permission logic
#         # This is a placeholder example
#         if self.is_admin:
#             return True
#         # Check if the user owns the file (example - needs implementation)
#         # if self.id == get_file_owner(filename):
#         #     return True
#         return False

# @login_manager.user_loader
# def load_user(user_id):
#     # Replace with your actual user loading logic
#     # This is a placeholder example
#     return User(user_id)

# Example of a login route (for demonstration purposes)
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     # Replace with your actual login logic
#     # This is a placeholder example
#     # For demonstration, we'll just create a dummy user
#     user = User(1, is_admin=True) # Example: User with ID 1 is an admin
#     login_user(user)
#     return redirect(url_for('upload_file'))

@app.route('/', methods=['GET', 'POST'])
# @login_required # Example of requiring login
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file'
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename) # Sanitize the filename
            unique_filename = generate_unique_filename(filename) # Generate a unique filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)

            # PDF Sanitization (Example - needs further implementation)
            if filename.lower().endswith('.pdf'):
                # Implement PDF sanitization techniques here
                # Examples: removing JavaScript, flattening form fields, stripping metadata
                # Consider using libraries like pdfminer.six or qpdf
                print("PDF Sanitization Placeholder - Implement actual sanitization!")

            return redirect(url_for('download_file', name=unique_filename))
        else:
            return 'Invalid file type'
    return '''
    <!doctype html>
    <html>
    <head>
        <title>Upload new File</title>
    </head>
    <body>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      {{ csrf_token() }}  <!-- Add this line -->
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    </body>
    </html>
    '''

@app.route('/uploads/<name>')
# @login_required # Example of requiring login
def download_file(name):
    # if not current_user.has_permission(name): # Example of permission check
    #     abort(403) # Forbidden

    """Downloads the file, but with a HUGE SECURITY WARNING!"""
    # SECURITY WARNING: Serving files directly from user uploads is extremely dangerous!
    # This is vulnerable to path traversal attacks.  A malicious user could craft a filename
    # like "../../../etc/passwd" to access sensitive files on the server.
    #
    # DO NOT USE THIS IN PRODUCTION!
    #
    # Instead, use a dedicated file server or a more secure method of serving files,
    # such as generating temporary URLs with limited access.

    # Check if the file exists before attempting to serve it
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], name)
    if not os.path.isfile(file_path):
        abort(404)  # Not Found

    return send_from_directory(app.config['UPLOAD_FOLDER'], name)

# Error handling
@app.errorhandler(404)
def page_not_found(error):
    return "Page not found", 404

@app.errorhandler(413)
def request_entity_too_large(error):
    return 'File Too Large', 413

# Content Security Policy (CSP) Example
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Example CSP
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    # NEVER USE debug=True IN PRODUCTION!
    app.run(debug=False, host='0.0.0.0', port=5000)

