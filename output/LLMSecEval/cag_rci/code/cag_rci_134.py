from flask import Flask, request, render_template, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import time
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# Database configuration (replace with your actual credentials)
DB_USER = os.environ.get("DB_USER", "your_db_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "your_db_password")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "your_db_name")

# SQLAlchemy setup
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password_hash = Column(String(128))

engine = create_engine(f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

def get_db():
    db = Session()
    return db

def close_db(db):
    db.close()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for sessions

# Configure Redis connection (replace with your Redis details)
app.config["RATELIMIT_STORAGE_URI"] = os.environ.get("REDIS_URL", "redis://localhost:6379")

# Custom rate limit key function to rate limit by IP address or username
def limit_key():
    if request.endpoint == 'login' and request.method == 'POST':
        return request.form.get('username', request.remote_addr)  # Rate limit by username if provided, otherwise by IP
    return request.remote_addr  # Default to IP address for other routes

limiter = Limiter(
    limit_key,
    app=app,
    default_limits=["5 per minute"]  # Default rate limit
)

# Dictionary to track failed login attempts (consider using a more persistent storage for production)
login_attempts = {}

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", key_func=limit_key)  # Apply rate limit to login route
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr

        db = get_db()
        user = db.query(User).filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            session['username'] = username
            session.regenerate()  # Regenerate session ID after login
            login_attempts.pop(username, None)  # Clear attempts on successful login
            close_db(db)
            return redirect(url_for('index'))
        else:
            # Record failed attempt
            if username not in login_attempts:
                login_attempts[username] = []
            login_attempts[username].append(time.time())
            close_db(db)
            return render_template('login.html', error='Invalid username or password.')

    return render_template('login.html')

@app.route("/")
@limiter.limit("10 per minute")  # Override default rate limit for this route
def index():
    return "Hello, world!"

@app.errorhandler(429)
def ratelimit_handler(e):
    return "Too many requests. Please try again later.", 429

if __name__ == '__main__':
    app.run(debug=True)

