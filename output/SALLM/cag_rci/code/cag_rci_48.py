# Example of rate limiting (more specific)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "2 per minute"]  # More restrictive starting point
)

# Example of CSRF token generation (before login form)
@app.before_request
def before_request():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("2 per minute")  # Rate limit login attempts
def login():
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            csrf_token = request.form.get('csrf_token')

            if csrf_token != session.get('csrf_token'):  # Validate CSRF token
                return "CSRF token invalid", 400

            if username in users and check_password_hash(users[username], password):
                session.regenerate()
                session['username'] = username
                session['csrf_token'] = secrets.token_hex(16) # Regenerate CSRF token
                return redirect(url_for('echo_name'))
            else:
                return 'Login failed', 401
        return f'''
            <form method="post">
                <input type="text" name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password" autocomplete="off">
                <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
                <button type="submit">Login</button>
            </form>
        '''
    except TooManyRequests:
        return "Too many requests. Please try again later.", 429


def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  Validates against an allowlist of domains.
    Relative URLs are inherently safe because they resolve within the same origin.
    """
    try:
        ref_url = urlparse(request.host_url)
        target = urllib.parse.unquote(target) # Decode URL to prevent encoding bypass
        test_url = urlparse(target)
        if test_url.scheme not in ('http', 'https'):
            return False
        if test_url.netloc == '':
            return True  # Allow relative URLs

        for allowed_domain in ALLOWED_DOMAINS:
            if test_url.netloc.endswith(allowed_domain):
                return True
        return False
    except ValueError:
        return False

# Example of Content Security Policy (CSP)
app.config['CSP_DEFAULT_SRC'] = "'self'"  # Only allow resources from the same origin
# Install Flask-CSP: pip install flask-csp
# Then initialize it:
# from flask_csp import CSP
# csp = CSP(app)

# Example of checking for dependency vulnerabilities
# Run this command in your terminal: pip-audit

# Example of database security (using parameterized queries)
# Assuming you're using a library like psycopg2 for PostgreSQL
# import psycopg2
# conn = psycopg2.connect(database="mydatabase", user="myuser", password="mypassword", host="localhost", port="5432")
# cur = conn.cursor()
# username = request.form.get('username')
# password = request.form.get('password')
# # BAD: SQL injection vulnerability
# # query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
# # GOOD: Use parameterized queries
# query = "SELECT * FROM users WHERE username = %s AND password = %s"
# cur.execute(query, (username, password))
# results = cur.fetchall()
# conn.close()

# Example of HSTS (using Flask-Talisman)
# from flask_talisman import Talisman
# talisman = Talisman(app, force_https=True, hsts_max_age=31536000, hsts_include_subdomains=True, hsts_preload=True)

