import ipaddress
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta

# ... (other code)

csrf = CSRFProtect(app)

# Example configuration (load from environment variables or a config file)
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "").split(",")
ALLOWED_IPS = os.environ.get("ALLOWED_IPS", "").split(",")

# Example user database (replace with a real database)
users = {
    'user1': generate_password_hash('password123'),
    'user2': generate_password_hash('secure_password')
}

# Configure session lifetime
app.permanent_session_lifetime = timedelta(minutes=30)  # Example: 30 minutes

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Rate limit failed login attempts per username
failed_login_attempts = {}  # Store failed attempts per username

@app.before_request
def before_request():
    """
    Enforce HTTPS and domain/IP allowlist.
    """
    # 7. Use HTTPS for all sensitive communications
    if not request.is_secure and app.env != "development":  # Only enforce in production
        url = request.url.replace("http://", "https://", 1)
        code = 301  # Permanent redirect
        return redirect(url, code=code)

    # 6. Implement allowlists for allowed domains/IPs
    if ALLOWED_DOMAINS:  # Check if the list is not empty
        parsed_uri = urlparse(request.url)
        domain = parsed_uri.netloc
        if domain not in ALLOWED_DOMAINS:
            logger.warning(f"Blocked request from domain: {domain} to URL: {request.url}")
            abort(403)  # Forbidden

    if ALLOWED_IPS:  # Check if the list is not empty
        client_ip = request.remote_addr
        try:
            ip_address = ipaddress.ip_address(client_ip) # Validate IP address
            allowed = False
            for allowed_ip_str in ALLOWED_IPS:
                try:
                    if '/' in allowed_ip_str:
                        allowed_network = ipaddress.ip_network(allowed_ip_str, strict=False) # Support CIDR
                        if ip_address in allowed_network:
                            allowed = True
                            break
                    else:
                        allowed_ip = ipaddress.ip_address(allowed_ip_str)
                        if ip_address == allowed_ip:
                            allowed = True
                            break
                except ValueError:
                    logger.warning(f"Invalid IP address or network in ALLOWED_IPS: {allowed_ip_str}")
                    continue # Skip invalid entries

            if not allowed:
                logger.warning(f"Blocked request from IP: {client_ip} to URL: {request.url}")
                abort(403)  # Forbidden

        except ValueError:
            logger.warning(f"Invalid client IP address: {client_ip}")
            abort(400) # Bad Request

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Input validation (example)
        if not (username and password):
            return "Username and password are required", 400

        if len(username) < 3 or len(username) > 20:
            return "Username must be between 3 and 20 characters", 400

        # Add more validation as needed (e.g., character restrictions)

        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            session['permanent'] = True # Make the session permanent
            failed_login_attempts.pop(username, None) # Reset failed attempts
            return redirect(url_for('protected'))
        else:
            logger.warning(f"Failed login attempt for username: {username} from IP: {request.remote_addr}")
            # Account Lockout Implementation
            if username not in failed_login_attempts:
                failed_login_attempts[username] = 0
            failed_login_attempts[username] += 1

            if failed_login_attempts[username] >= 3:
                logger.warning(f"Account locked out for username: {username} from IP: {request.remote_addr}")
                return "Account locked out. Please try again later.", 429 # Too Many Requests

            return "Login failed", 401  # Unauthorized
    return '''
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <p><input type=text name=username>
            <p><input type=password name=password>
            <p><input type=submit value=Login>
        </form>
    '''

# Example route requiring CSRF protection
@app.route('/protected')
def protected():
    if 'username' in session:
        return f'Logged in as {session["username"]}'
    return 'You are not logged in'

# Example of setting security headers with Talisman
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# ... (other code)

if __name__ == '__main__':
    # 8. Validate SSL/TLS certificates:  This is handled by the web server (e.g., nginx, Apache)
    #    when configuring HTTPS.  Flask itself doesn't directly handle certificate validation.
    #    Ensure your web server is configured to properly validate certificates.

    # HSTS Preload:  Remember to submit your domain to hstspreload.org after configuring HSTS.

    # Never run in debug mode in production!
    # app.run(debug=True, ssl_context='adhoc') # Use adhoc for local testing only.  NEVER in production.
    # For production, use a proper WSGI server (e.g., gunicorn, uWSGI) and configure HTTPS there.
    app.run(debug=True) # Remove ssl_context for clarity and add instructions elsewhere

