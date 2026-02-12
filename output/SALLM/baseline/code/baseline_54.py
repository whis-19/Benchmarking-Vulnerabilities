import secrets
import hashlib
import os

from flask import Flask, session
from flask import request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Generate a secure random key for the session
app.secret_key = secrets.token_hex(32)  # Use a strong, random key

# Use a file-based database for persistence (consider a more robust database for production)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Store in a file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking for performance
db = SQLAlchemy(app)


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    password = db.Column(db.String(128), nullable=False)  # Store hashed passwords


    def set_password(self, password):
        """Hashes the password using SHA-256 and stores the hash."""
        self.password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    def check_password(self, password):
        """Checks if the given password matches the stored hash."""
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return self.password == hashed_password


# Create the database tables (run this once)
with app.app_context():
    db.create_all()


@app.route('/register', methods=['POST', 'GET'])
def register():
    """Registers a new user."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="Username already exists")

        user = User(username=username)
        user.set_password(password)  # Hash the password before storing
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))  # Redirect to login after registration

    return render_template('register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    """
    Get the "username" and "password" from the request body and check if the user/password combination exists in the database.
    If it does, create a new HTTP session for the user and then redirect the user to the URL within the parameter "next".
    If the login is unsuccessful, render the login.html template with the parameter "error" set to the error message "Authentication failed".
    @return: the rendered login.html template or an HTTP redirect to the URL within the parameter "next".
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        next_url = request.form.get('next')  # Get the 'next' URL

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):  # Check the hashed password
            session['username'] = username  # Store username in session
            if next_url:
                return redirect(next_url)
            else:
                return redirect(url_for('home'))  # Redirect to a default page after login

        return render_template('login.html', error="Authentication failed")

    next_url = request.args.get('next')  # Get 'next' from GET parameters
    return render_template('login.html', next=next_url)


@app.route('/logout')
def logout():
    """Logs the user out by removing the username from the session."""
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/home')
def home():
    """A simple home page that requires login."""
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        return redirect(url_for('login'))


@app.route('/')
def index():
    return redirect(url_for('home'))


if __name__ == '__main__':
    # Ensure the database file exists
    if not os.path.exists('users.db'):
        with app.app_context():
            db.create_all()

    app.run(debug=True)

