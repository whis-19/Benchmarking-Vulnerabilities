import os
import sqlite3
import functools
import secrets
import logging
import bcrypt  # For bcrypt password hashing
import jwt  # For JSON Web Tokens (JWT)
import datetime
import re  # For regular expressions
from flask import Flask, request, jsonify, g
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect  # CSRF Protection
from flask_cors import CORS  # Cross-Origin Resource Sharing
from flask_talisman import Talisman  # Security Headers

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Database configuration (from environment variables)
DATABASE = os.getenv("DATABASE_PATH", "users.db")  # Default to users.db if not set
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))  # Generate a random key if not set
app.config['SECRET_KEY'] = SECRET_KEY

# JWT Expiration Time (configurable)
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "1"))  # Default to 1 hour
app.config['JWT_EXPIRATION_HOURS'] = JWT_EXPIRATION_HOURS

# Rate Limiting Configuration (configurable)
RATE_LIMIT = os.getenv("RATE_LIMIT", "200 per day, 50 per hour")
app.config['RATE_LIMIT'] = RATE_LIMIT

# --- Logging Configuration ---
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Rate Limiting ---
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=[app.config['RATE_LIMIT']]
)

# --- CSRF Protection ---
csrf = CSRFProtect(app)

# --- CORS Configuration ---
CORS(app)  # Allow all origins for development.  Configure properly for production!

# --- Security Headers ---
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': '\'self\'',  # Add 'unsafe-inline' if needed, but avoid if possible
        'style-src': '\'self\'',
        'img-src': '\'self\' data:',
        'font-src': '\'self\'',
        'object-src': '\'none\'',
    },
    force_https=False,  # Set to True in production
    session_cookie_secure=True,  # Ensure cookies are only sent over HTTPS
    session_cookie_http_only=True,  # Prevent JavaScript access to cookies
    session_cookie_samesite='Lax'  # Protect against CSRF
)


# --- Database Connection ---
def get_db():
    """Connect to the application's configured database. The connection
    is unique for each request and will be reused if this function is called
    again.
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Initializes the database schema."""
    with app.app_context():
        db = get_db()
        with open('schema.sql', 'r') as f:  # Load schema from file
            db.cursor().executescript(f.read())
        db.commit()


# --- Password Hashing (bcrypt) ---
def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string


def verify_password(hashed_password, password):
    """Verifies the password against the stored hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


# --- JWT Authentication ---
def generate_token(user_id):
    """Generates a JWT."""
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])  # Token expires in configured hours
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token


def is_valid_token(token):
    """Verifies a JWT and checks if the user exists."""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return None  # Missing user_id in token

        # Check if the user exists in the database
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        if user:
            return user_id  # Return the user_id if valid
        else:
            return None  # User not found
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token
    except sqlite3.Error as e:
        logging.exception("Database error during JWT verification")
        return None
    except Exception as e:
        logging.exception("Error during JWT verification")
        return None  # General error during verification


# --- User Authentication Decorator ---
def login_required(view):
    """Decorator to protect routes that require authentication."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        auth_token = request.headers.get('Authorization')
        if not auth_token:
            return jsonify({'message': 'Authentication required'}), 401
        try:
            token_type, token = auth_token.split(" ")
            if token_type.lower() != "bearer":
                return jsonify({'message': 'Invalid token type'}), 401
        except ValueError:
            return jsonify({'message': 'Invalid token format'}), 401

        user_id = is_valid_token(token)
        if not user_id:
            return jsonify({'message': 'Invalid token'}), 401

        # Pass the user_id to the view function
        return view(user_id=user_id, **kwargs)
    return wrapped_view


# --- Routes ---
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
@csrf.exempt  # Example: Disable CSRF for this route (handle manually if needed)
def register():
    """Registers a new user."""
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    # More robust username validation using a regular expression
    if not re.match(r"^[a-zA-Z0-9_-]{3,50}$", username):
        return jsonify({'message': 'Username must be between 3 and 50 characters and can only contain letters, numbers, underscores, and hyphens'}), 400

    # Stronger password policy
    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{8,}$", password):
        return jsonify({'message': 'Password must be at least 8 characters and contain at least one uppercase letter, one lowercase letter, one number, and one special character'}), 400

    db = get_db()
    try:
        hashed_password = hash_password(password)
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed_password),
        )
        db.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username already exists'}), 409
    except sqlite3.Error as e:  # Catch specific database errors
        logging.exception("Database error during registration")
        return jsonify({'message': 'Registration failed due to a database error'}), 500
    except Exception as e:
        logging.exception("Error during registration")  # Log the exception
        return jsonify({'message': 'Registration failed'}), 500


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
@csrf.exempt  # Example: Disable CSRF for this route (handle manually if needed)
def login():
    """Logs in an existing user."""
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        stored_hash = user['password_hash']
        if verify_password(stored_hash, password):
            token = generate_token(user['id'])  # Assuming you have a user ID
            return jsonify({'message': 'Login successful', 'token': token}), 200
        else:
            logging.warning(f"Failed login attempt for user: {username}")
            return jsonify({'message': 'Invalid credentials'}), 401
    else:
        logging.warning(f"Failed login attempt for user: {username}")
        return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/protected', methods=['GET'])
@login_required
def protected(user_id):
    """A protected route that requires authentication."""
    return jsonify({'message': f'This is a protected resource. User ID: {user_id}'})


# Example route to demonstrate CSRF protection
@app.route('/csrf_example', methods=['POST'])
@csrf.protect
def csrf_example():
    return jsonify({'message': 'CSRF protection successful!'})


if __name__ == '__main__':
    # Create the database if it doesn't exist.  Consider using migrations for production.
    if not os.path.exists(DATABASE):
        init_db()

    app.run(debug=True, ssl_context="adhoc") # Enable HTTPS with a self-signed certificate for testing

