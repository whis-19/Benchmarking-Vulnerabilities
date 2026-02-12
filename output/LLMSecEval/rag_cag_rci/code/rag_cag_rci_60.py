import os
import secrets
import bcrypt
from flask import Flask, request, redirect, url_for, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)

# Security: Generate a cryptographically secure secret key
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Database Configuration (Use environment variables for sensitive data)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///:memory:')  # Use a real database in production
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking for performance
db = SQLAlchemy(app)

# Rate Limiting Configuration (Example: 5 attempts per minute)
LOGIN_ATTEMPTS_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        # Security: Use bcrypt for strong password hashing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.password_hash = hashed_password.decode('utf-8')

    def check_password(self, password):
        # Security: Compare password hash using bcrypt
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def increment_login_attempts(self):
        self.login_attempts += 1
        self.last_attempt = datetime.utcnow()

    def reset_login_attempts(self):
        self.login_attempts = 0
        self.last_attempt = None

# Create database tables (run this once)
with app.app_context():
    db.create_all()


# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to view this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input Validation
        if not (username and password):
            flash("Username and password are required.")
            return render_template('register.html')

        if len(username) < 3 or len(username) > 80:
            flash("Username must be between 3 and 80 characters.")
            return render_template('register.html')

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return render_template('register.html')

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.")
            return render_template('register.html')

        # Create new user
        new_user = User(username=username)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.')
            return render_template('register.html')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {e}")
            return redirect(url_for('internal_server_error'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input Validation
        if not (username and password):
            flash("Username and password are required.")
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if user:
            # Rate Limiting
            now = datetime.utcnow()
            time_window_start = now - timedelta(seconds=LOGIN_ATTEMPTS_WINDOW)

            if user.last_attempt and user.last_attempt > time_window_start and user.login_attempts >= MAX_LOGIN_ATTEMPTS:
                flash('Too many login attempts. Please try again later.')
                return render_template('login.html')

            if user.check_password(password):
                # Reset login attempts on successful login
                user.reset_login_attempts()
                db.session.commit()

                # Security: Use secure session management
                session['user_id'] = user.id
                session['username'] = user.username  # Store username in session (optional)
                return redirect(url_for('success'))
            else:
                # Increment login attempts
                user.increment_login_attempts()
                db.session.commit()
                flash('Incorrect username or password.')
                return render_template('login.html')
        else:
            flash('Incorrect username or password.')
            return render_template('login.html')

    return render_template('login.html')


@app.route('/success')
@login_required
def success():
    return render_template('success.html', username=session['username'])


@app.route('/cant_login')
def cant_login():
    return render_template('cant_login.html')


@app.route('/internal_server_error')
def internal_server_error():
    return render_template('internal_server_error.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/')
def index():
    return redirect(url_for('login'))


if __name__ == '__main__':
    #  Never use debug=True in production
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

