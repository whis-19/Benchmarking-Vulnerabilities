from functools import wraps
from flask import abort
from flask import g, Flask, request, redirect, session, url_for
import os
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
import secrets  # For generating secure random values
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy  # Import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a strong, random secret key.  Store this securely in a real application
# (e.g., environment variable, configuration file).  NEVER hardcode it in the source code.
app.secret_key = secrets.token_hex(24)  # More secure than os.urandom

# Configure session security
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF

csrf = CSRFProtect(app)

# Configure the database (replace with your actual database settings)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Example: SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Disable tracking modifications
db = SQLAlchemy(app)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"]  # Adjust as needed
)

# Define the User model
class User(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

with app.app_context():
    db.create_all()  # Create the database tables

def ensure_logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        if 'user_id' not in session:  # Check if user_id exists in session
            return redirect(url_for('login'))  # Use url_for for better maintainability
        return f(*args, **kws)
    return decorated_function

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)]) # Enforce password length
    submit = SubmitField('Submit')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

#the login page
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Apply rate limiting
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()  # Query the database

        if user and user.check_password(password): # Verify password hash
            session['user_id'] = user.id  # Store user ID in session
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('secret'))
        else:
            logging.warning(f"Failed login attempt for user {username} from {request.remote_addr}.")
            return 'Invalid credentials'  # Generic error message

    return '''
        <html><form method="POST" action="{{ url_for('login') }}">
            {{ form.csrf_token }}
            <p><input type="text" name="username"></p>
            <p><input type="password" name="password"></p>
            <p><button type="submit">Submit</button></p>
        </form></html>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists. Please choose a different one."

        # Create a new user
        new_user = User(username=username)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        logging.info(f"New user registered: {username}")
        return redirect(url_for('login'))  # Redirect to login page after registration

    return '''
        <html><form method="POST" action="{{ url_for('register') }}">
            {{ form.csrf_token }}
            <p><input type="text" name="username" placeholder="Username"></p>
            <p><input type="password" name="password" placeholder="Password"></p>
            <p><input type="password" name="confirm_password" placeholder="Confirm Password"></p>
            <p><button type="submit">Register</button></p>
        </form></html>
    '''


#the home page
@app.route('/')
def index():
    return '''<html>
    Hello! <a href='./login'>Login here</a> <a href='./register'>Register here</a>
    </html>'''

#user settings page
@app.route('/settings')
@ensure_logged_in
def settings():
    '''
    If the user is authenticated, show the settings page.
    '''
    user = User.query.get(session['user_id'])
    return "Settings Page - Logged in as " + user.username

@app.route('/secret')
@ensure_logged_in
def secret():
    return "Secret page! Only logged in users can see this."

@app.route('/logout')
@ensure_logged_in
def logout():
    session.pop('user_id', None)  # Remove user_id from session
    return redirect(url_for('index'))  # Redirect to the home page

if __name__ == '__main__':
    # NEVER use debug=True in production!
    app.run(debug=True)  # Remove debug=True for production

