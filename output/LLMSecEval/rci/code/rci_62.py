import os
import bcrypt
from flask import Flask, render_template, request, session, redirect, url_for, escape
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from bleach import clean
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

app = Flask(__name__)

# **IMPORTANT:**  Replace with a secure, randomly generated secret key.
#  This is crucial for session management and preventing session hijacking.
app.secret_key = os.urandom(24)  # Generates 24 random bytes for the key

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["20 per minute"]  # Example: 20 requests per minute
)

# Configure session security
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only set to True if using HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Example: 30-minute session

# Database configuration (SQLite for simplicity, but consider PostgreSQL or MySQL for production)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Use an absolute path for production
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking modifications for performance

# Initialize SQLAlchemy
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    hashed_password = Column(String(100), nullable=False)

Base.metadata.create_all(engine)  # Create the table if it doesn't exist

Session = sessionmaker(bind=engine)


# Define forms using Flask-WTF
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=100),
                                                     EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


def hash_password(password):
    """Hashes the password using bcrypt with a randomly generated salt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def verify_password(entered_password, stored_hashed_password):
    """Verifies the entered password against the stored hashed password."""
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_hashed_password)


@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts to 5 per minute
def login():
    """Handles the login page."""
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        db_session = Session()
        user = db_session.query(User).filter_by(username=username).first()

        if user:
            if verify_password(password, user.hashed_password):
                session['username'] = username
                db_session.close()
                return redirect(url_for('session_page'))
            else:
                error = 'Incorrect username or password'
        else:
            error = 'Incorrect username or password'
        db_session.close()

    return render_template('login.html', form=form, error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles the registration page."""
    form = RegistrationForm()
    error = None
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        db_session = Session()
        existing_user = db_session.query(User).filter_by(username=username).first()

        if existing_user:
            error = "Username already exists"
        else:
            # Sanitize the username
            username = clean(username, strip=True)

            hashed_password = hash_password(password)
            new_user = User(username=username, hashed_password=hashed_password)
            db_session.add(new_user)
            db_session.commit()
            db_session.close()
            return redirect(url_for('login'))
        db_session.close()

    return render_template('register.html', form=form, error=error)


@app.route('/session')
def session_page():
    """Displays the session page if the user is logged in."""
    if 'username' in session:
        return render_template('session.html', username=escape(session['username']))
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Logs the user out by removing the username from the session."""
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    # **IMPORTANT:**  Never run in production with debug=True.
    #  It exposes sensitive information and allows arbitrary code execution.
    app.run(debug=True)

