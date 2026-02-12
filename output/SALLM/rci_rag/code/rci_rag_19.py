# Configuration (example using environment variables)
import os
from datetime import timedelta
from flask import Flask, request, Response, session
from flask_session import Session  # Import Flask-Session

MAX_REQUESTS_PER_MINUTE = int(os.environ.get("MAX_REQUESTS_PER_MINUTE", 10))
CSRF_SALT = os.environ.get("CSRF_SALT", "csrf-salt")
SESSION_LIFETIME_DAYS = int(os.environ.get("SESSION_LIFETIME_DAYS", 30))

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(days=SESSION_LIFETIME_DAYS)

# Configure Flask-Session (Redis example)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True  # Optional, but recommended
app.config['SESSION_KEY_PREFIX'] = 'session:'  # Optional prefix for Redis keys
app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379, db=0)  # Configure Redis connection
Session(app)  # Initialize Flask-Session


# CSRF Protection
serializer = URLSafeTimedSerializer(app.secret_key, salt=CSRF_SALT)

# Rate Limiting (using Redis)
import redis
import time
import uuid

redis_client = redis.Redis(host='localhost', port=6379, db=0)  # Configure Redis connection

def is_rate_limited(ip_address):
    key = f"rate_limit:{ip_address}"
    now = int(time.time())
    with redis_client.pipeline() as pipe:
        pipe.zremrangebyscore(key, 0, now - 60)  # Remove entries older than 1 minute
        pipe.zcard(key)  # Get the current count
        pipe.zadd(key, {now: now})  # Add the current request
        pipe.expire(key, 60)  # Set expiration for the key
        count = pipe.execute()[1]  # Get the count from the pipeline result

    return count >= MAX_REQUESTS_PER_MINUTE


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Generate a CSRF token and store it in the session
        csrf_token = serializer.dumps(request.remote_addr)
        session['csrf_token'] = csrf_token
        return f'''
            <form method="POST">
                <input type="text" name="username" maxlength="50">
                <input type="password" name="password" maxlength="50">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <button type="submit">Login</button>
            </form>
        '''
    elif request.method == 'POST':
        username = request.form.get('username', '').encode('utf-8').decode('utf-8') # Encoding
        password = request.form.get('password', '').encode('utf-8').decode('utf-8') # Encoding
        csrf_token = request.form.get('csrf_token')

        # Validate CSRF token
        try:
            real_ip = serializer.loads(csrf_token, max_age=3600) # Token expires after 1 hour
            if real_ip != request.remote_addr:
                logger.warning(f"CSRF token IP mismatch for user {username} from IP {request.remote_addr}")
                return Response("CSRF token IP mismatch!", status=400)
        except Exception as e:
            logger.warning(f"CSRF token invalid for user {username} from IP {request.remote_addr}: {e}")
            return Response("CSRF token invalid!", status=400)


        # In a real application, you would validate the username and password
        # against a database or other authentication system.
        # Example using bcrypt:
        # Retrieve hashed password from database (replace with your actual database query)
        # For demonstration purposes, we'll hardcode a hashed password
        hashed_password_from_db = bcrypt.hashpw(b"password", bcrypt.gensalt())

        if username == "test" and bcrypt.checkpw(password.encode('utf-8'), hashed_password_from_db):
            session['logged_in'] = True
            session.permanent = True  # Make the session permanent
            session.regenerate()  # Regenerate session ID after login
            logger.info(f"Login successful for user {username} from IP {request.remote_addr}")
            return "Login successful!"
        else:
            logger.warning(f"Login failed for user {username} from IP {request.remote_addr}")
            return "Login failed."

@app.route('/example')
def example_route():
    try:
        # Some code that might raise an exception
        raise ValueError("Example error")
    except Exception as e:
        error_id = uuid.uuid4()
        logger.exception(f"Error ID: {error_id} - Unexpected error: {e}")
        return Response(f"An unexpected error occurred. Please contact support and provide error ID: {error_id}", status=500)

