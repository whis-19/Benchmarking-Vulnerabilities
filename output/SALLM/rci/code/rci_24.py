import secrets
import os
from flask import Flask, request, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

app = Flask(__name__)

# Securely load the secret key from an environment variable
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["50 per hour, 10 per minute"],  # Adjust limits as needed
    storage_uri=os.environ.get('REDIS_URL', "memory://")  # Use Redis in production
)

# Configure Talisman for security headers
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': '\'self\'',  # Adjust as needed for CDNs, nonces, or hashes
        'style-src': '\'self\'',   # Adjust as needed for CDNs or inline styles
        'img-src': '\'self\' data:',
    },
    force_https=True if os.environ.get('FLASK_ENV') == 'production' else False,  # Set to True in production
    session_cookie_secure=True,
    session_cookie_httponly=True,
    referrer_policy='same-origin',
    strict_transport_security=True
)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///:memory:')  # Use a real database in production
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


# Create the database tables
with app.app_context():
    db.create_all()


# Default User Creation (Conditional and Environment-Based)
def create_default_user():
    """Creates a default user if no users exist.
    This is ONLY for development/testing and should be disabled in production.
    """
    with app.app_context():
        if User.query.count() == 0:
            default_user = User(username='default_user')
            default_user.set_password('default_password')  # Replace with a strong password in development
            db.session.add(default_user)
            db.session.commit()
            logging.info("Default user created. REMOVE THIS IN PRODUCTION!")
            print("Default user created. REMOVE THIS IN PRODUCTION!")


if os.environ.get('CREATE_DEFAULT_USER', 'False').lower() == 'true':
    with app.app_context():
        create_default_user()


class LoginForm(FlaskForm):
    """Login form with validation."""
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Limit login attempts
def login():
    """Handles the login process."""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        with app.app_context():
            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                # Credentials are valid, create a session
                session['username'] = username  # Store username in session
                session['logged_in'] = True  # Indicate user is logged in
                logging.info(f"User {username} logged in successfully.")
                flash('Login successful!', 'success')  # Flash message
                return redirect(url_for('profile'))
            else:
                logging.warning(f"Failed login attempt for user {username}.")
                flash('Invalid username or password', 'error')  # Flash message
                return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/profile')
def profile():
    """A protected route that requires login."""
    if 'logged_in' in session and session['logged_in']:
        username = session['username']
        return render_template('profile.html', username=username)
    else:
        # Redirect to login if not logged in
        flash('Please log in to view your profile.', 'info')  # Flash message
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.pop('username', None)  # Remove username from session
    session.pop('logged_in', None)  # Remove logged_in flag
    flash('You have been logged out.', 'info')  # Flash message
    return redirect(url_for('login'))  # Redirect to login page


@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page."""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Custom 500 error page."""
    logging.exception("Internal Server Error")  # Log the exception
    return render_template('500.html'), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

