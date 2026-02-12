from flask import Flask, request, abort, Response, render_template, flash, redirect, url_for
import os
from defusedxml import ElementTree as ET  # Import defusedxml for safer XML parsing
from werkzeug.utils import secure_filename  # Import secure_filename for safer filename handling
import bcrypt
import logging
import secrets  # For generating a strong secret key
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField, StringField, PasswordField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
import psycopg2  # For PostgreSQL database connection (example)

app = Flask(__name__)

# Generate a strong secret key and store it securely (e.g., environment variable)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(16))  # Fallback to a generated key if not in env
app.config['SECRET_KEY'] = SECRET_KEY

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure allowed file extensions and upload folder
UPLOAD_FOLDER = 'uploads'  # Create this folder in your project directory
ALLOWED_EXTENSIONS = {'xml'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB file size limit

# Create the upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Adjust limits as needed
)

# Database configuration (replace with your actual database details)
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "your_db_name")
DB_USER = os.environ.get("DB_USER", "your_db_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "your_db_password")


def get_hashed_password_from_db(userid):
    """
    Retrieves the hashed password from the database.

    Args:
        userid: The user ID.

    Returns:
        The hashed password as a string, or None if the user is not found.
    """
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cur = conn.cursor()
        cur.execute("SELECT hashed_password FROM users WHERE userid = %s", (userid,))  # Parameterized query
        result = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        if result:
            return result[0]  # Assuming hashed_password is the first column
        else:
            return None
    except psycopg2.Error as e:
        logging.error(f"Database error: {e}")
        return None


def checkPassword(userid, password):
    """
    Checks if the provided password matches the hashed password in the database.

    Args:
        userid: The user ID.
        password: The password to check.

    Returns:
        True if the password is correct, False otherwise.
    """
    # Retrieve the hashed password from your database based on the userid
    try:
        hashed_password_from_db = get_hashed_password_from_db(userid)  # Replace with your database lookup
    except Exception as e:
        logging.error(f"Error retrieving password from database: {e}")
        flash("An error occurred during authentication.") # Generic error message
        return False  # Or raise an exception, depending on your error handling policy

    if hashed_password_from_db:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password_from_db.encode('utf-8'))
    else:
        return False


def hash_password(password):
    """
    Hashes the provided password using bcrypt.

    Args:
        password: The password to hash.

    Returns:
        The hashed password as a string.
    """
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')  # Store this in your database


def allowed_file(filename):
    """
    Checks if the file extension is allowed.

    Args:
        filename: The filename.

    Returns:
        True if the extension is allowed, False otherwise.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class UploadForm(FlaskForm):
    file = FileField('XML File', validators=[DataRequired()])
    userid = StringField('User ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Upload')


@app.route('/upload', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Limit uploads to 10 per minute per IP
def upload():
    """
    Handles XML file uploads, performs authentication, and parses the XML.
    """
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        userid = form.userid.data
        password = form.password.data

        if not checkPassword(userid, password):
            logging.warning(f"Authentication failed for user: {userid}")
            os.remove(filepath)
            flash("Invalid userid or password")
            return render_template('upload.html', form=form)

        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            print(f"Root element: {root.tag}")
            logging.info(f"Successfully processed XML file: {filename}")
            os.remove(filepath)
            flash("File uploaded and processed successfully")
            return render_template('upload.html', form=form)

        except ET.ParseError as e:
            logging.error(f"Invalid XML: {str(e)}")
            os.remove(filepath)
            flash(f"Invalid XML: {str(e)}")
            return render_template('upload.html', form=form)
        except Exception as e:
            logging.exception(f"Error processing XML: {e}")
            os.remove(filepath)
            flash("Error processing XML")
            return render_template('upload.html', form=form)

    return render_template('upload.html', form=form)


@app.route('/')
def index():
    return render_template('index.html')


@app.before_request
def before_request():
    """
    Enforce Content-Type header for the /upload endpoint.
    """
    if request.endpoint == 'upload' and request.method == 'POST':
        if request.content_type != 'multipart/form-data':
            logging.warning(f"Invalid Content-Type: {request.content_type}")
            abort(400, description="Content-Type must be multipart/form-data")


@app.errorhandler(413)
def request_entity_too_large(e):
    """Handles the 413 error (Request Entity Too Large) when the file size exceeds the limit."""
    logging.warning("File size exceeds the allowed limit.")
    return "File size exceeds the allowed limit (16MB).", 413


if __name__ == '__main__':
    # Example of hashing a password (only for demonstration, do this during user registration)
    # hashed_password = hash_password("secure_password")
    # print(f"Hashed password: {hashed_password}")

    app.run(debug=False)  # Disable debug mode in production

