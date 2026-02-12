# is_safe_url improvement
from urllib.parse import urlparse, urljoin, urlunparse

def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.  Prevents open redirects.
    Severity: High
    Attack Vector: Phishing, Malware Distribution
    OWASP Reference: https://owasp.org/www-project-top-ten/
    """
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))

        # Reconstruct the URL to normalize it
        reconstructed_url = urlunparse(test_url)

        return test_url.scheme in ('http', 'https') and \
               ref_url.netloc == test_url.netloc and \
               reconstructed_url.startswith(request.host_url) # Ensure it starts with our host
    except Exception as e:
        logger.error(f"Error parsing URL: {e}")
        return False

# Login route - username enumeration fix
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """
    Simulated login route with rate limiting.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # In a real application, you would compare the hashed password
        # with a stored hash from a database.
        # Retrieve the hashed password from the database
        # stored_hashed_password = bcrypt.generate_password_hash("password").decode('utf-8') # This is just for testing purposes.  NEVER store passwords like this
        # Replace with database lookup
        user = get_user(username) # Assuming get_user returns None if user doesn't exist
        if user:
            stored_hashed_password = user[2] # Assuming the hashed password is the third column
        else:
            stored_hashed_password = None

        if user and bcrypt.check_password_hash(stored_hashed_password, password):
            # Regenerate session to prevent session fixation attacks
            session.clear()
            session['logged_in'] = True
            session.permanent = True  # Make the session "permanent"
            app.permanent_session_lifetime = timedelta(minutes=30)  # Set session timeout
            return "Login successful!"
        else:
            logger.warning(f"Failed login attempt for user: {username} from {request.remote_addr}")
            return "Invalid credentials", 401 # Generic error message

    return """
    <form method="post">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    """

# Logout route - clear the session
@app.route('/logout')
def logout():
    """
    Logout route.
    """
    session.clear() # Invalidate the entire session
    return "Logged out"

