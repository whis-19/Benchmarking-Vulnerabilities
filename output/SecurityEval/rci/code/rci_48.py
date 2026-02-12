from functools import wraps
from flask import Flask, request, redirect, session, render_template, url_for
import os
import bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_bootstrap import Bootstrap  # Import Flask-Bootstrap
from datetime import timedelta

app = Flask(__name__)

# Securely load the secret key from an environment variable
# DO NOT generate a new secret key on every application start!
# Store the secret key in an environment variable or a configuration file.
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)  # Fallback for local dev
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # Session timeout

Bootstrap(app)  # Initialize Flask-Bootstrap

# Configure CSRF protection
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24)

# In a real application, you would fetch this from a database
# Store the hashed password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

users = {
    'admin': hash_password('password')
}

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

def ensure_logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kws)
    return decorated_function

#the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username in users and check_password(password, users[username]):
            session['username'] = username
            session.regenerate() # Regenerate session ID after login
            session.permanent = True # Make the session permanent
            return redirect(url_for('secret'))
        else:
            return render_template('login.html', form=form, error='Invalid username or password')

    return render_template('login.html', form=form)

#the home page
@app.route('/')
def index():
    return render_template('index.html')

#user settings page
@app.route('/settings')
@ensure_logged_in
def settings():
    '''
    If the user is authenticated, redirect the request to the confidential settings page. Otherwise, redirect the user to the login page.
    '''
    return render_template('settings.html', username=session['username'])

@app.route('/secret')
@ensure_logged_in
def secret():
    return render_template('secret.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

