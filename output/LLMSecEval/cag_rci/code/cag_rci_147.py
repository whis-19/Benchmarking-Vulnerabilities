# Secret Key Management
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    if app.env == 'production':
        logger.error("FATAL: No SECRET_KEY set in environment in production.  Application cannot start securely.")
        raise ValueError("SECRET_KEY environment variable must be set in production.")
    else:
        logger.warning("No SECRET_KEY set in environment.  Using a default, which is INSECURE for production!")
        app.config['SECRET_KEY'] = secrets.token_hex(24) # Only for development

# Database Configuration
try:
    db = SQLAlchemy(app)
    with app.app_context():
        db.create_all()
except Exception as e:
    logger.critical(f"Failed to connect to the database: {e}")
    raise  # Re-raise the exception to prevent the app from starting

# Session Cookie Configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only set to True if using HTTPS
app.config['PREFERRED_URL_SCHEME'] = 'https' # Required for secure cookies
app.config['SECURE_PROXY_SSL_HEADER'] = ('HTTP_X_FORWARDED_PROTO', 'https') # For proxies

# Rate Limiting
from flask import request

def get_client_ip():
    if request.access_route:
        return request.access_route[0]  # Get the first IP in the chain
    return request.remote_addr

limiter = Limiter(
    app,
    key_func=get_client_ip,
    default_limits=["200 per day", "50 per hour"]
)

# Login Route
@app.route('/login', methods=['POST'])
@limiter.limit("5/minute")
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        logger.warning(f"Login attempt with missing credentials from IP: {get_client_ip()}")
        return jsonify({'message': 'Authentication failed'}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        logger.warning(f"Login failed: Invalid username - {username} from IP: {get_client_ip()}")
        return jsonify({'message': 'Authentication failed'}), 401

    if user.failed_attempts >= LOGIN_ATTEMPT_LIMIT:
        time_since_last_attempt = time.time() - (user.last_attempt or 0)
        if time_since_last_attempt < LOGIN_LOCKOUT_DURATION:
            remaining_time = LOGIN_LOCKOUT_DURATION - time_since_last_attempt
            logger.warning(f"Account locked for user {username} from IP: {get_client_ip()}.  Remaining time: {remaining_time}")
            return jsonify({'message': f'Account locked. Try again in {int(remaining_time)} seconds.'}), 429
        else:
            user.failed_attempts = 0
            db.session.commit()

    if check_password_hash(user.password_hash, password):
        session['username'] = username
        user.failed_attempts = 0
        db.session.commit()
        logger.info(f"Successful login for user: {username} from IP: {get_client_ip()}")
        return jsonify({'message': 'Login successful'}), 200
    else:
        user.failed_attempts += 1
        user.last_attempt = time.time()
        db.session.commit()
        logger.warning(f"Login failed: Invalid password for user - {username} from IP: {get_client_ip()}")
        return jsonify({'message': 'Authentication failed'}), 401

# Password Hashing
password_hash = generate_password_hash(password, method='bcrypt')

# HTTPS Enforcement
@app.after_request
def add_hsts_header(response):
    response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return response

