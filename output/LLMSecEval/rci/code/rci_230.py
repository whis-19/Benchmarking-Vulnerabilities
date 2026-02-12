import os
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))  # Get from env var or generate
DATABASE = os.environ.get('DATABASE_PATH', 'users.db')  # Get from env var or default
app.config['SESSION_PERMANENT'] = False  # Sessions expire when browser closes (more secure default)

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)
# Consider different limits for different routes/user roles. See Flask-Limiter documentation:
# https://flask-limiter.readthedocs.io/en/stable/

# Database setup (using SQLite for simplicity)
def get_db_connection():
    """Connects to the database."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None  # Or raise the exception if appropriate

def init_db():
    """Initializes the database (creates the users table if it doesn't exist)."""
    conn = get_db_connection()
    if conn:
        with conn:  # Use 'with' for automatic commit/rollback
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            """)
        conn.close()

# Call init_db when the app starts
with app.app_context():
    init_db()


# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20),
                                                   Regexp(r'^[a-zA-Z0-9_]+$',
                                                          message='Username must contain only letters, numbers, and underscores')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        try:
            conn = get_db_connection()
            if conn is None:
                flash("Database connection failed.", "error")
                return render_template('register.html', form=form)

            with conn:
                # Hash the password before storing it
                password_hash = generate_password_hash(password)

                # Sanitize the username (remove leading/trailing whitespace)
                username = username.strip()

                # Insert the username and hashed password into the database
                conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                             (username, password_hash))

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different username.', 'error')
            return render_template('register.html', form=form)

        except sqlite3.Error as e:  # Catch more specific database errors
            flash(f"Database error: {e}", "error")
            return render_template('register.html', form=form)

        finally:
            if conn:
                conn.close()

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        if conn is None:
            flash("Database connection failed.", "error")
            return render_template('login.html', form=form)

        try:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

            if user:
                # Verify the password against the stored hash
                if check_password_hash(user['password_hash'], password):
                    session['username'] = username  # Store the username in the session
                    flash('Login successful!', 'success')
                    return redirect(url_for('profile'))  # Redirect to a logged-in page
                else:
                    flash('Incorrect password.', 'error')
            else:
                flash('Username not found.', 'error')

        except sqlite3.Error as e:
            flash(f"Database error: {e}", "error")
            return render_template('login.html', form=form)

        finally:
            if conn:
                conn.close()

    return render_template('login.html', form=form)


@app.route('/profile')
def profile():
    if 'username' in session:
        return render_template('profile.html', username=session['username'])
    else:
        flash('Please log in to view your profile.', 'info')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove the username from the session
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)

# Important Security Considerations:
# 1.  CSRF Protection:  Ensure `{{ form.csrf_token }}` is included in *every* form that accepts user input (POST, PUT, DELETE).
# 2.  Session Security:  For production environments, consider using a secure session store (e.g., Redis) and setting `session.permanent = True` appropriately.
# 3.  Rate Limiting:  Adjust rate limits based on your application's needs and consider different limits for different routes/user roles.
# 4.  Input Validation:  Thoroughly validate all user input to prevent various attacks.
# 5.  Database Security:  Use parameterized queries to prevent SQL injection.  Consider using an ORM for more robust database interaction.
# 6.  Secret Key:  Never hardcode the secret key in your code.  Always store it in an environment variable.
# 7.  Error Handling:  Implement robust error handling to prevent sensitive information from being exposed.
# 8.  HTTPS:  Always use HTTPS in production to encrypt communication between the client and server.

