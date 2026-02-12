import os
import secrets
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_csp import CSP
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a strong secret key
app.config['CSP_POLICY'] = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'connect-src': '\'self\'',
    'frame-ancestors': '\'none\'', # Prevent clickjacking
}

csp = CSP(app)

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# In-memory user database (replace with a secure database in production)
# NEVER HARDCODE CREDENTIALS IN PRODUCTION
users = {
    'admin': generate_password_hash('P@$$wOrd'),  # Store password hashes, not plain text
    'user': generate_password_hash('anotherP@$$wOrd')
}

# CSRF protection (using Flask-WTF)
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=255)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET'])
@limiter.limit("5/minute") # Limit login attempts
def login():
    form = LoginForm()
    return render_template('login.html', form=form)


@app.route('/do_login', methods=['POST'])
@limiter.limit("5/minute") # Limit login attempts
def do_login():
    form = LoginForm(request.form)
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            flash('Login successful!', 'success')
            if username == 'admin':
                return redirect(url_for('admin_page'))
            else:
                return redirect(url_for('home')) # Redirect to a non-admin page
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
    else:
        flash('Invalid form data', 'error')
        return redirect(url_for('login'))


@app.route('/admin')
@login_required
def admin_page():
    if session['username'] != 'admin':
        abort(403)  # Forbidden
    return render_template('admin.html', username=session['username'])


@app.route('/home')
@login_required
def home():
    return render_template('home.html', username=session['username'])


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))


# Example route to demonstrate input sanitization
@app.route('/profile', methods=['POST'])
@login_required
def update_profile():
    new_name = request.form.get('name')

    # Sanitize input (example: strip whitespace and limit length)
    if new_name:
        new_name = new_name.strip()
        new_name = new_name[:100]  # Limit length to 100 characters

        # Escape for HTML rendering (important!)
        from markupsafe import escape
        escaped_name = escape(new_name)

        # In a real application, you would update the user's profile in the database
        flash(f'Profile updated! Name: {escaped_name}', 'success')
    else:
        flash('Name cannot be empty.', 'error')

    return redirect(url_for('home'))


# Error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


if __name__ == '__main__':
    #  NEVER USE debug=True IN PRODUCTION!
    #  It can expose sensitive information.
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS in production

