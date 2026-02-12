import secrets
import hashlib  # Consider bcrypt or argon2 instead
import os
import re  # For input validation
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

app = Flask(__name__)

# Use a more secure method for generating a secret key
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random secret key
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24) # Secure CSRF secret key

# Use a file-based database for persistence (consider a more robust database for development/testing).
# For production, use a more robust database like PostgreSQL or MySQL.  SQLite is generally NOT recommended
# for production due to concurrency limitations and potential data corruption issues in high-traffic scenarios.
# It *can* be suitable for very small, low-traffic applications where simplicity is paramount, but for anything
# beyond a toy application, a more robust database is essential.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking for performance
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
csrf.init_app(app)  # Initialize CSRF protection

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)  # Store password hash, not the password itself
    token = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        """Hashes the password using SHA-256.  **IMPORTANT: Consider bcrypt or argon2 for production.**"""
        self.password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return self.password_hash == hashlib.sha256(password.encode('utf-8')).hexdigest()


# CSRF Form Example
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')


with app.app_context():
    db.create_all()  # Create the database tables


@app.route('/register', methods=['POST'])
def register():
    """Registers a new user."""
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")  # Get the password from the request

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    # Example Input Validation
    if not (6 <= len(username) <= 32):  # Example length check
        return jsonify({"message": "Username must be between 6 and 32 characters"}), 400

    if not re.match("^[a-zA-Z0-9_]+$", username): # Example character check (alphanumeric and underscore only)
        return jsonify({"message": "Username must contain only alphanumeric characters and underscores"}), 400

    if not (8 <= len(password) <= 64): # Example password length check
        return jsonify({"message": "Password must be between 8 and 64 characters"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 409  # Conflict status code

    token = secrets.token_hex(16)  # Generate a random 16-byte token

    # Tokens should *not* be stored in plain text in the database.  Consider encrypting the token
    # before storing it.  This example does not implement encryption.
    new_user = User(username=username, token=token)
    new_user.set_password(password)  # Hash the password before storing

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully", "token": token}), 201  # Created status code
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "Registration failed (integrity error)"}), 500
    except Exception as e:
        db.session.rollback()
        print(f"Error during registration: {e}")  # Log the error - include the exception!
        return jsonify({"message": "Registration failed"}), 500


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Example limit on login attempts
def login():
    """Authenticates a user based on username and password."""
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # The token should *only* be transmitted over HTTPS.
        # Consider using HTTP-only cookies for storage on the client-side to prevent XSS attacks.
        return jsonify({"message": "Authentication successful", "token": user.token}), 200
    else:
        return jsonify({"message": "Authentication failed"}), 401  # Unauthorized status code


@app.route('/csrf_example', methods=['GET', 'POST'])
def csrf_example():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Process the form data here
        return jsonify({"message": "Form submitted successfully"}), 200
    return '''
    <form method="post">
        {{ form.csrf_token }}
        <p>{{ form.username.label }} {{ form.username(size=20) }}</p>
        <p>{{ form.password.label }} {{ form.password(size=20) }}</p>
        <p>{{ form.submit() }}</p>
    </form>
    '''


if __name__ == '__main__':
    # NEVER run in debug mode in production!  This is a HUGE security risk.
    # Debug mode exposes sensitive information, enables interactive debuggers, and can allow arbitrary code execution.
    # Running in debug mode in production is akin to leaving the front door of your house wide open with a sign that says "Rob Me!".
    app.run(debug=True)

# Dependency Management:
# Use a tool like pip-tools (pip install pip-tools) to manage your dependencies.
# pip-tools allows you to create reproducible builds by pinning the exact versions of your dependencies.
# This helps prevent vulnerabilities that can arise from using outdated or compromised packages.
# Create a requirements.in file with your top-level dependencies (e.g., Flask, SQLAlchemy, etc.).
# Then, run `pip-compile requirements.in` to generate a requirements.txt file with pinned versions.
# Finally, use `pip-sync` to install the dependencies from requirements.txt.

