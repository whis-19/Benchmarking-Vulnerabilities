from flask import Flask, request, session, redirect, url_for, abort
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash  # Use generate_password_hash for storing passwords
import bcrypt  # Recommended for password hashing
import secrets  # For generating secure random values

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Securely generate a secret key

# Example of a more robust lockout policy
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_BASE = 60  # Seconds

def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_from_db(username)

        if user:
            if user['locked_out'] and user['lockout_expiry'] > datetime.utcnow():
                time_remaining = user['lockout_expiry'] - datetime.utcnow()
                return f"Account locked out.  Please try again in {time_remaining.seconds} seconds.", 403

            # Use bcrypt for password verification
            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                # Successful login - reset failed attempts
                reset_failed_attempts(username)
                session['username'] = username
                session['last_login'] = datetime.utcnow()  # Store login time
                session.regenerate() # Regenerate session ID
                return redirect(url_for('protected'))
            else:
                # Failed login - increment failed attempts
                if not increment_failed_attempts(username):
                    return "Account locked out. Please try again later.", 403 # Account locked during increment
                return "Login failed.", 401
        else:
            return "Login failed.", 401

def increment_failed_attempts(username):
    try:
        user = get_user_from_db(username, for_update=True) # Lock the row for update
        if not user:
            return False  # User doesn't exist

        if user['locked_out'] and user['lockout_expiry'] > datetime.utcnow():
            return False # Already locked out

        failed_attempts = user.get('failed_attempts', 0) + 1
        lockout_expiry = None
        locked_out = False

        if failed_attempts >= MAX_LOGIN_ATTEMPTS:
            locked_out = True
            lockout_duration = LOCKOUT_DURATION_BASE * (2**(failed_attempts - MAX_LOGIN_ATTEMPTS)) # Exponential backoff
            lockout_expiry = datetime.utcnow() + timedelta(seconds=lockout_duration)

        update_user_in_db(username, failed_attempts=failed_attempts, locked_out=locked_out, lockout_expiry=lockout_expiry)
        return True
    except DatabaseLockError: # Or whatever exception your DB raises for locking
        return False # Indicate failure due to locking

def reset_failed_attempts(username):
    update_user_in_db(username, failed_attempts=0, locked_out=False, lockout_expiry=None)

# Example of password hashing (when creating a new user)
def create_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    # Store hashed_password in the database

# Example of session regeneration
@app.before_request
def before_request():
    session.permanent = True  # Make sessions permanent
    app.permanent_session_lifetime = timedelta(minutes=30)  # Set session lifetime
    session.modified = True # Ensure session is updated

# Example of validating redirect URL (very basic)
def safe_redirect(url):
    if url.startswith('/'):  # Only allow relative redirects within the application
        return redirect(url)
    else:
        abort(400)  # Bad Request

# Example of using safe_redirect after login
def protected():
    if 'username' in session:
        next_url = request.args.get('next')  # Get the intended destination
        if next_url:
            return safe_redirect(next_url)
        else:
            return "Protected area"
    else:
        return redirect(url_for('login'))

