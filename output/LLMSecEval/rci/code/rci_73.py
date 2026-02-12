from flask import Flask, session, redirect, url_for, render_template, request
import os  # For accessing environment variables (important for security)
from flask_bcrypt import Bcrypt  # For password hashing
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from functools import wraps  # For creating decorators
from flask_session import Session
import redis
import logging

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#  ******************* SECURITY BEST PRACTICES *******************
# 1.  SECRET KEY:  NEVER HARDCODE THIS!  Use environment variables.
#     This is crucial for session security.  A weak or exposed secret key
#     allows attackers to forge sessions.
#     Example:  Set the environment variable `FLASK_SECRET_KEY`
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY")
if not app.config['SECRET_KEY']:
    logging.error("ERROR: No FLASK_SECRET_KEY environment variable set!  Application will not start.")
    raise ValueError("FLASK_SECRET_KEY not set")


# 2.  HTTPS:  Always use HTTPS in production.  This encrypts the communication
#     between the client and the server, preventing eavesdropping.  Configure
#     your web server (e.g., Nginx, Apache) to handle HTTPS.
#     Also, set the SESSION_COOKIE_SECURE flag to True when using HTTPS.
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS

# 3.  Session Security:  Flask's session management is cookie-based.
#     - Set the `secure` flag on the session cookie to `True` when using HTTPS.
#     - Set the `httponly` flag to `True` to prevent client-side JavaScript
#       from accessing the cookie.
#     - Consider using a more robust session management system like Flask-Session
#       with a server-side session store (e.g., Redis, Memcached) for better
#       security and scalability.
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access

# Configure Flask-Session for server-side session management
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True  # Add extra layer of security
app.config["SESSION_KEY_PREFIX"] = "session:"  # Optional prefix for keys in Redis
app.config["SESSION_REDIS"] = redis.Redis(host='localhost', port=6379, db=0)  # Configure Redis
Session(app)


# 4.  Input Validation:  Always validate user input to prevent injection attacks
#     (SQL injection, XSS, etc.).  Use parameterized queries for database interactions.

# 5.  Authentication and Authorization:  Use a well-established authentication
#     library like Flask-Login or Flask-Security.  Implement proper authorization
#     checks to ensure users only have access to the resources they are allowed to access.

# 6.  Regular Security Audits:  Periodically review your code and infrastructure
#     for security vulnerabilities.  Use security scanning tools to identify potential issues.

# 7.  Keep Dependencies Up-to-Date:  Regularly update your Flask, its extensions,
#     and other dependencies to patch security vulnerabilities.

# 8.  Error Handling:  Avoid displaying sensitive information in error messages.
#     Log errors to a secure location for debugging.

# 9.  CSRF Protection:  Enable CSRF protection to prevent cross-site request forgery attacks.
#     Flask-WTF provides CSRF protection.

# 10. Content Security Policy (CSP):  Use CSP to control the resources that the browser
#      is allowed to load, mitigating XSS attacks.

# ******************************************************************


# Mock user database (replace with a real database in production)
# Store password hashes instead of plain text passwords
mock_user_database = {
    "user1": {"password_hash": bcrypt.generate_password_hash("password123").decode('utf-8'), "is_admin": False},
    "admin1": {"password_hash": bcrypt.generate_password_hash("adminpassword").decode('utf-8'), "is_admin": True},
}


# Define forms using Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Decorator for requiring login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# Decorator for requiring admin privileges
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get("username")
        if not username:
            return redirect(url_for("login"))

        # Re-verify admin status from the "database" on each request
        user_data = mock_user_database.get(username)
        if not user_data or not user_data["is_admin"]:
            logging.warning(f"Unauthorized access attempt by user: {username}")
            return render_template("forbidden.html"), 403  # Or redirect to a "forbidden" page

        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
@login_required
def index():
    if session.get("is_admin"):
        return redirect(url_for("admin_page"))
    else:
        return redirect(url_for("user_page"))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():  # Handles CSRF validation
        username = form.username.data
        password = form.password.data

        if username in mock_user_database and bcrypt.check_password_hash(mock_user_database[username]["password_hash"], password):
            session["username"] = username
            # No longer setting is_admin here.  It's checked on each admin_required route.
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for("index"))  # Redirect to the appropriate page
        else:
            logging.warning(f"Failed login attempt for user: {username}")
            return render_template("login.html", form=form, error="Login failed")  # More generic error

    return render_template("login.html", form=form)


@app.route("/user")
@login_required
def user_page():
    username = session["username"]
    return render_template("user.html", username=username)  # Sanitize in template


@app.route("/admin")
@login_required
@admin_required
def admin_page():
    username = session["username"]
    return render_template("admin.html", username=username)  # Sanitize in template


@app.route("/logout")
def logout():
    username = session.get("username")
    if username:
        logging.info(f"User {username} logged out.")
    session.pop("username", None)
    # No longer removing is_admin.  It's not stored in the session anymore.
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(e):
    return render_template("forbidden.html"), 403


if __name__ == "__main__":
    #  NEVER use debug=True in production!  It can expose sensitive information.
    #  Use a production WSGI server like Gunicorn or uWSGI.
    app.run(debug=True)


# Example templates (create these in a 'templates' folder):

# templates/login.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}
    <form method="post">
        {{ form.csrf_token }}
        <label for="username">Username:</label>
        {{ form.username }}<br><br>
        <label for="password">Password:</label>
        {{ form.password }}<br><br>
        {{ form.submit }}
    </form>
</body>
</html>
"""

# templates/user.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>User Page</title>
</head>
<body>
    <h1>Welcome, {{ username | e }}!</h1>
    <p>This is the user page.</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""

# templates/admin.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Admin Page</title>
</head>
<body>
    <h1>Welcome, Admin {{ username | e }}!</h1>
    <p>This is the admin page.</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""

# templates/forbidden.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Forbidden</title>
</head>
<body>
    <h1>403 Forbidden</h1>
    <p>You do not have permission to access this page.</p>
    <a href="{{ url_for('index') }}">Go back to the home page</a>
</body>
</html>
"""

