from flask import Flask, render_template, request, redirect, url_for, session, abort, g
import os
import secrets
import bcrypt
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__)

# Generate a secure random key for the session
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# CSRF Protection
csrf = CSRFProtect(app)

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]
)

# Configure security headers
talisman = Talisman(app,
                    content_security_policy={
                        'default-src': '\'self\'',
                        'script-src': ['\'self\'', '\'nonce-{nonce}\''],  # Use nonces
                        'style-src': ['\'self\'', '\'nonce-{nonce}\'']   # Use nonces
                    },
                    force_https=True,
                    frame_options='DENY',
                    content_type_nosniff=True,
                    referrer_policy='same-origin',
                    session_cookie_secure=True,  # Ensure session cookie is secure
                    session_cookie_httponly=True) # Prevent JS access to session cookie


# In a real application, you would store user credentials in a database
# For this example, we'll use a hardcoded admin user
ADMIN_USERNAME = "admin"

# Securely hash the password using bcrypt
def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def verify_password(entered_password, stored_hash):
    """Verifies a password against a bcrypt hash."""
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_hash.encode('utf-8'))

ADMIN_PASSWORD_HASH = hash_password("strong_password")  # Replace with a strong password

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    """
    Displays the login form.
    """
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username == ADMIN_USERNAME and verify_password(password, ADMIN_PASSWORD_HASH):
            session['logged_in'] = True
            # In a real app, store user roles in the session (e.g., session['role'] = 'admin')
            return redirect(url_for('admin_page'))
        else:
            return render_template('login.html', form=form, error="Invalid login attempt")  # Generic error message

    return render_template('login.html', form=form)


@app.route('/admin')
def admin_page():
    """
    Displays the admin page.  Requires the user to be logged in and have admin role.
    """
    if not session.get('logged_in'):
        abort(403)  # Or redirect to login page
    # In a real app, check the user's role:
    # if session.get('role') != 'admin':
    #     abort(403)
    return render_template('admin.html')


@app.route('/logout')
def logout():
    """
    Logs the user out by clearing the session.
    """
    session.pop('logged_in', None)
    # In a real app, also remove the role: session.pop('role', None)
    return redirect(url_for('login'))


@app.errorhandler(403)
def forbidden(e):
    """
    Handles 403 Forbidden errors.
    """
    return "Access denied. You are not authorized to view this page.", 403

@app.before_request
def add_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)
    app.jinja_env.globals['csp_nonce'] = g.csp_nonce

@app.after_request
def inject_csp_nonce(response):
    if 'text/html' in response.content_type:
        response.headers['Content-Security-Policy'] = response.headers['Content-Security-Policy'].format(nonce=g.csp_nonce)
    return response


@app.route('/')
def index():
    """
    A simple index page.
    """
    return "Welcome!  <a href='/login'>Login</a>"


if __name__ == '__main__':
    #  Never run in production with debug=True.  It exposes sensitive information.
    #  Set FLASK_ENV=production in your environment
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)) , debug=os.environ.get('FLASK_ENV') != 'production')

