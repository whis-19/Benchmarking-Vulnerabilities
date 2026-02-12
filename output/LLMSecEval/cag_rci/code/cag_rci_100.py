# Configuration
DATABASE = os.environ.get("DATABASE_URL", "users.db")
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    logging.critical("FLASK_SECRET_KEY not set.  Application cannot start.")
    raise RuntimeError("FLASK_SECRET_KEY not set.  Application cannot start.") # Or exit the program

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

# Session management - consider a server-side session store like Redis
# Example using Flask-Session:
# from flask_session import Session
# app.config["SESSION_TYPE"] = "redis"  # Or "memcached", "filesystem", etc.
# app.config["SESSION_PERMANENT"] = True
# app.config["SESSION_USE_SIGNER"] = True  # Sign the session cookie
# app.config["SESSION_KEY_PREFIX"] = "session:"  # Optional prefix for session keys
# Session(app)

# HTTPS Enforcement and Security Headers
from flask_talisman import Talisman

talisman = Talisman(app, force_https=True,
                    content_security_policy={
                        'default-src': '\'self\'',
                        'script-src': ['\'self\'', '\'unsafe-inline\''], # Adjust as needed
                        'style-src': ['\'self\'', '\'unsafe-inline\''],  # Adjust as needed
                        'img-src': '*'
                    })

# Logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Database setup
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_login_attempts INTEGER DEFAULT 0,  -- For account locking
            lockout_expiry DATETIME  -- For account locking
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Input Validation
def validate_username(username):
    if not isinstance(username, str):
        return False, "Username must be a string."
    if not (3 <= len(username) <= 50):
        return False, "Username must be between 3 and 50 characters."
    if not username.isalnum():
        return False, "Username must contain only alphanumeric characters."
    # Add username blacklist here if needed
    return True, None

def validate_password(password):
    if not isinstance(password, str):
        return False, "Password must be a string."
    if not (8 <= len(password) <= 100):
        return False, "Password must be between 8 and 100 characters."

    # Require at least one uppercase letter, one lowercase letter, one number, and one special character
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."

    # Consider checking against a password blacklist (Have I Been Pwned API) here

    return True, None

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Registration Route
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    username_valid, username_error = validate_username(username)
    password_valid, password_error = validate_password(password)

    if not username_valid:
        return jsonify({'error': username_error}), 400
    if not password_valid:
        return jsonify({'error': password_error}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    except Exception as e:
        logging.error(f"Database error: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

# Login Route
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, failed_login_attempts, lockout_expiry FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            stored_hash = result['password_hash']
            failed_login_attempts = result['failed_login_attempts']
            lockout_expiry = result['lockout_expiry']

            # Account Locking Logic (Example - needs more robust implementation)
            if lockout_expiry and datetime.datetime.now() < datetime.datetime.fromisoformat(lockout_expiry):
                return jsonify({'error': 'Account locked.  Please try again later.'}), 403

            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                # Reset failed login attempts on successful login
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET failed_login_attempts = 0, lockout_expiry = NULL WHERE username = ?", (username,))
                conn.commit()
                conn.close()

                session.regenerate() # Regenerate session ID
                session.permanent = True
                session['username'] = username
                session['last_activity'] = datetime.datetime.now().isoformat() # For idle timeout
                return jsonify({'message': 'Login successful'}), 200
            else:
                # Increment failed login attempts
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?", (username,))
                conn.commit()
                conn.close()

                # Lock account after too many failed attempts (Example)
                if failed_login_attempts + 1 >= 5:
                    lockout_time = datetime.datetime.now() + timedelta(minutes=15) # Lock for 15 minutes
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET lockout_expiry = ? WHERE username = ?", (lockout_time.isoformat(), username,))
                    conn.commit()
                    conn.close()
                    return jsonify({'error': 'Account locked.  Please try again later.'}), 403

                # Generic error message to prevent username enumeration
                return jsonify({'error': 'Invalid username or password'}), 401
        else:
            # Generic error message to prevent username enumeration
            return jsonify({'error': 'Invalid username or password'}), 401
    except Exception as e:
        logging.error(f"Database error: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

# Logout Route
@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    session.clear()  # Invalidate the entire session on the server-side
    return jsonify({'message': 'Logged out successfully'}), 200

# Protected Route
@app.route('/protected')
@login_required
def protected():
    # Idle Timeout Implementation (Example)
    if 'last_activity' in session:
        last_activity = datetime.datetime.fromisoformat(session['last_activity'])
        if datetime.datetime.now() - last_activity > timedelta(minutes=10): # 10 minutes of inactivity
            session.clear()
            return jsonify({'error': 'Session timed out due to inactivity'}), 401
        session['last_activity'] = datetime.datetime.now().isoformat() # Update last activity
    else:
        session.clear()
        return jsonify({'error': 'Session timed out'}), 401

    return jsonify({'message': f'Hello, {session["username"]}!'}), 200

# Error handling
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429

if __name__ == '__main__':
    app.run(debug=True) # REMOVE debug=True IN PRODUCTION

