import os
import secrets
import sqlite3
import logging
from flask import Flask, render_template, request, flash, redirect, url_for
import bcrypt  # Import bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from bleach import clean  # For sanitization
import re  # For regular expression validation
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only enable in HTTPS environment
logging.basicConfig(filename='error.log', level=logging.ERROR)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",  # Use a persistent storage for production
    strategy="fixed-window"
)

# Example Form for CSRF Protection
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])  # Added Email validator
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

def is_password_complex(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isalnum() for char in password):
        return False
    return True

def hash_password(password):
    # Argon2 is generally preferred over bcrypt now
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')  # Store as string

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_db():
    db = sqlite3.connect('database.db')
    db.row_factory = sqlite3.Row
    return db

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit registration attempts
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = clean(form.username.data)  # Sanitize username
        email = clean(form.email.data)  # Sanitize email
        password = form.password.data

        # Additional username validation (e.g., no special characters)
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            flash("Username can only contain letters, numbers, and underscores.", "error")
            return render_template('register.html', form=form)

        if not is_password_complex(password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, numeric, and special characters.', 'error')
            return render_template('register.html', form=form)

        db = get_db()
        try:
            hashed_password = hash_password(password)
            db.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                       (username, hashed_password, email))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('That username is already taken. Please choose a different one.', 'error') # More specific for usability
        finally:
            db.close()  # Ensure database connection is always closed

    return render_template('register.html', form=form)

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("An error occurred:")  # Log the full exception
    return "An internal server error occurred.", 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return "Too many requests. Please try again later.", 429

if __name__ == '__main__':
    app.run(debug=True)

