from flask import Flask, request, session, redirect, url_for, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import logging
import html  # For escaping HTML
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong secret key
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only enable this if you're using HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # or 'Strict' for more security

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Example SQLite database
db = SQLAlchemy(app)

# CSRF Protection
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24)  # Another secret key for CSRF
csrf = CSRFProtect(app)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute"]  # Adjust as needed
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Database Interaction
def get_user_from_db(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return {'username': user.username, 'password_hash': user.password_hash}
    else:
        return None

# Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=100)])
    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limiting for login attempts
def login():
    """Handles user login with rate limiting and password hashing."""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user_data = get_user_from_db(username)

        if user_data:
            if check_password_hash(user_data['password_hash'], password):
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('index'))
            else:
                # Log the failed password attempt (without revealing the username)
                app.logger.warning(f"Failed password attempt from {request.remote_addr} for user {username}")
                return "Invalid credentials.", 401  # Generic error message
        else:
            # Log the failed username attempt
            app.logger.warning(f"Invalid username attempt: {username} from {request.remote_addr}")
            return "Invalid credentials.", 401  # Generic error message

    return render_template('login.html', form=form)

@app.route('/')
def index():
    if session.get('logged_in'):
        return f"Logged in as {session['username']}"
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create the database tables
        # Example of creating a user (run this once to add a user to the database)
        if not get_user_from_db('testuser'):
            hashed_password = generate_password_hash('secure_password', method='pbkdf2:sha256', salt_length=8)
            new_user = User(username='testuser', password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
    app.run(debug=True, ssl_context="adhoc") # Use adhoc for testing, replace with proper certs for production

