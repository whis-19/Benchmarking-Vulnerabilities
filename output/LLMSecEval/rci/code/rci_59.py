import os
from flask import Flask, request, redirect, url_for, render_template, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session  # For server-side session management
import secrets
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


app = Flask(__name__)

# Generate a strong secret key
app.config['SECRET_KEY'] = secrets.token_hex(24)

# Configure server-side sessions (using filesystem for example)
app.config['SESSION_TYPE'] = 'filesystem'  # Or 'redis', 'memcached', 'mongodb'
app.config['SESSION_PERMANENT'] = True  # Make sessions permanent
app.config['SESSION_USE_SIGNER'] = True  # Add extra layer of security
app.config['SESSION_KEY_PREFIX'] = 'session:'  # Prefix for session keys
app.config['SESSION_FILE_DIR'] = 'flask_session'  # Directory to store session files
app.config['SESSION_FILE_THRESHOLD'] = 500  # Number of session files before cleanup
app.config['SESSION_FILE_MODE'] = 0o700  # Permissions for session files
app.config['SESSION_REFRESH_EACH_REQUEST'] = True # Refresh session on each request
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF (more modern approach)


Session(app)

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Example limits
)


# Database setup (using SQLite for simplicity - consider PostgreSQL for production)
#  SQLite is suitable for development, but PostgreSQL (or another robust database)
#  is highly recommended for production environments.
DATABASE = 'users.db'

def create_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

create_table()  # Create the table if it doesn't exist


# Custom validator for username (example)
def validate_username(form, field):
    if not field.data.isalnum():
        raise ValidationError('Username must be alphanumeric.')
    if len(field.data) < 4 or len(field.data) > 20:
        raise ValidationError('Username must be between 4 and 20 characters.')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20), validate_username])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


def register_user(username, password):
    """Registers a new user in the database."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Use Werkzeug's password hashing
        password_hash = generate_password_hash(password)

        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, password_hash))
        conn.commit()
        conn.close()
        logging.info(f"User registered: {username}")
        return True  # Registration successful
    except sqlite3.IntegrityError:
        logging.warning(f"Registration failed: Username already exists: {username}")
        if conn:
            conn.close()
        return False # Username already exists
    except Exception as e:
        logging.error(f"Error during registration: {e}")
        if conn:
            conn.close()
        return False


def login(username, password):
    """Authenticates the user against the database."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            password_hash_from_db = result[0]

            # Use Werkzeug's password checking
            if check_password_hash(password_hash_from_db, password):
                logging.info(f"User logged in: {username}")
                return True  # Login successful
            else:
                logging.warning(f"Login failed: Incorrect password for user: {username}")
                return False  # Incorrect password
        else:
            logging.warning(f"Login failed: Username not found: {username}")
            return False  # Username not found
    except Exception as e:
        logging.error(f"Error during login: {e}")
        if conn:
            conn.close()
        return False


@app.route('/')
def index():
    return redirect(url_for('login_route'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login_route():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if login(username, password):
            session['username'] = username  # Store username in session
            logging.info(f"Session created for user: {username}")
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit registration attempts
def register_route():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if register_user(username, password):
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login_route'))
        else:
            flash('Username already exists.', 'error')
            return render_template('register.html', form=form)
    return render_template('register.html', form=form)


@app.route('/home')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        flash('Please login to access this page.', 'warning')
        return redirect(url_for('login_route'))  # Redirect to login if not logged in

@app.route('/logout')
def logout():
    username = session.get('username')
    session.pop('username', None)  # Remove username from session
    logging.info(f"User logged out: {username}")
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    import os
    debug = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.run(debug=debug, host="0.0.0.0")


# HTML Templates (place these in a 'templates' folder)

# templates/login.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="post" action="/login" novalidate>
            {{ form.csrf_token }}
            <div class="form-group">
                <label for="username">Username:</label>
                {{ form.username(class="form-control") }}
                {% if form.username.errors %}
                    <ul class="errors">
                        {% for error in form.username.errors %}
                            <li>{{ error }}</li>
                        {% endfor %}
                    </ul>
                {% endif %}
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                {{ form.password(class="form-control") }}
                {% if form.password.errors %}
                    <ul class="errors">
                        {% for error in form.password.errors %}
                            <li>{{ error }}</li>
                        {% endfor %}
                    </ul>
                {% endif %}
            </div>
            {{ form.submit(class="btn btn-primary") }}
        </form>
        <p>Don't have an account? <a href="/register">Register</a></p>
    </div>
</body>
</html>
"""

# templates/register.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1>Register</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="post" action="/register" novalidate>
            {{ form.csrf_token }}
            <div class="form-group">
                <label for="username">Username:</label>
                {{ form.username(class="form-control") }}
                {% if form.username.errors %}
                    <ul class="errors">
                        {% for error in form.username.errors %}
                            <li>{{ error }}</li>
                        {% endfor %}
                    </ul>
                {% endif %}
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                {{ form.password(class="form-control") }}
                {% if form.password.errors %}
                    <ul class="errors">
                        {% for error in form.password.errors %}
                            <li>{{ error }}</li>
                        {% endfor %}
                    </ul>
                {% endif %}
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm Password:</label>
                {{ form.confirm_password(class="form-control") }}
                {% if form.confirm_password.errors %}
                    <ul class="errors">
                        {% for error in form.confirm_password.errors %}
                            <li>{{ error }}</li>
                        {% endfor %}
                    </ul>
                {% endif %}
            </div>
            {{ form.submit(class="btn btn-primary") }}
        </form>
        <p>Already have an account? <a href="/">Login</a></p>
    </div>
</body>
</html>
"""

# templates/home.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Home</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1>Welcome, {{ username }}!</h1>
        <p>You are logged in.</p>
        <a href="/logout" class="btn btn-danger">Logout</a>
    </div>
</body>
</html>
"""

