from flask import Flask, session, redirect, url_for, render_template, request, abort
import secrets  # For generating secure session keys
import os  # For accessing environment variables (important for security)
from flask_bcrypt import Bcrypt  # For password hashing
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
from functools import wraps  # For creating decorators
import logging

app = Flask(__name__)
bcrypt = Bcrypt(app)

#  ******************* SECURITY BEST PRACTICES *******************
# 1.  SECRET KEY:  NEVER HARDCODE THIS!  Use environment variables.
#     This is crucial for session security.  A weak or exposed secret key
#     allows attackers to forge sessions.
#     Example:  Set the environment variable `FLASK_SECRET_KEY`
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError("FLASK_SECRET_KEY environment variable must be set in production!")
    print("WARNING:  No FLASK_SECRET_KEY environment variable set!  This is insecure.")
    #  Generate a random key for development ONLY.  NEVER use this in production.
    app.secret_key = secrets.token_hex(32)  # Generates a 64-character hex string

# 2.  HTTPS:  Always use HTTPS in production.  This encrypts the communication
#     between the client and the server, preventing eavesdropping.  Configure
#     your web server (e.g., Nginx, Apache) to handle HTTPS.
#     Also, set SESSION_COOKIE_SECURE = True in production.
if os.environ.get("FLASK_ENV") == "production":
    app.config['SESSION_COOKIE_SECURE'] = True

# 3.  Session Security:  Flask's session management is cookie-based.
#     - Set the `secure` flag on the session cookie to `True` when using HTTPS.
#     - Set the `httponly` flag to `True` to prevent client-side JavaScript
#       from accessing the cookie.
#     - Consider using a more robust session management system like Flask-Session
#       with a server-side session store (e.g., Redis, Memcached) for better
#       security and scalability.
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access

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
#     See the errorhandler decorator below.

# 9.  CSRF Protection:  Enable CSRF protection to prevent cross-site request forgery attacks.
#     Flask-WTF provides CSRF protection.

# 10. Content Security Policy (CSP):  Use CSP to control the resources that the browser
#      is allowed to load, mitigating XSS attacks.

# ******************************************************************

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Mock user database (replace with a real database in production)
# Store password hashes instead of plain passwords
mock_user_database = {
    "user1": {"password_hash": bcrypt.generate_password_hash("password123").decode('utf-8'), "is_admin": False, "user_id": 1},
    "admin1": {"password_hash": bcrypt.generate_password_hash("adminpassword").decode('utf-8'), "is_admin": True, "user_id": 2},
}


# Define forms using Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20), Regexp(r'^[a-zA-Z0-9]+$', message="Username must contain only letters and numbers")])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


# Authorization decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return render_template("403.html"), 403  # Or redirect to a "forbidden" page

        user = next((user for user in mock_user_database.values() if user["user_id"] == user_id), None)
        if not user or not user["is_admin"]:
            return render_template("403.html"), 403
        return f(*args, **kwargs)

    return decorated_function


@app.errorhandler(404)
def page_not_found(e):
    # Log the error
    logging.warning(f"Page not found: {request.path}")
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    # Log the error
    logging.exception(f"Internal server error: {e}")
    return render_template('500.html'), 500


@app.route("/")
@login_required
def index():
    user_id = session.get("user_id")
    user = next((user for user in mock_user_database.values() if user["user_id"] == user_id), None)
    if user and user["is_admin"]:
        return redirect(url_for("admin_page"))
    else:
        return redirect(url_for("user_page"))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():  # Handles CSRF validation
        username = form.username.data
        password = form.password.data

        if username in mock_user_database and bcrypt.check_password_hash(
                mock_user_database[username]["password_hash"], password):
            session["user_id"] = mock_user_database[username]["user_id"]
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for("index"))  # Redirect to the appropriate page
        else:
            logging.warning(f"Failed login attempt for user {username}.")
            return render_template("login.html", form=form, error="Invalid username or password")

    return render_template("login.html", form=form)


@app.route("/user")
@login_required
def user_page():
    user_id = session.get("user_id")
    user = next((user for user in mock_user_database.values() if user["user_id"] == user_id), None)
    username = "Unknown User"
    if user:
        username = next((name for name, data in mock_user_database.items() if data["user_id"] == user_id), "Unknown User")
    return render_template("user.html", username=username)


@app.route("/admin")
@login_required
@admin_required
def admin_page():
    user_id = session.get("user_id")
    user = next((user for user in mock_user_database.values() if user["user_id"] == user_id), None)
    username = "Unknown Admin"
    if user:
        username = next((name for name, data in mock_user_database.items() if data["user_id"] == user_id), "Unknown Admin")
    return render_template("admin.html", username=username)


@app.route("/logout")
@login_required
def logout():
    user_id = session.get("user_id")
    user = next((user for user in mock_user_database.values() if user["user_id"] == user_id), None)
    username = "Unknown"
    if user:
        username = next((name for name, data in mock_user_database.items() if data["user_id"] == user_id), "Unknown")
    logging.info(f"User {username} logged out.")
    session.pop("user_id", None)
    return redirect(url_for("login"))


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
        <input type="text" id="username" name="{{ form.username.name }}" required><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="{{ form.password.name }}" required><br><br>
        <button type="submit">Login</button>
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
    <h1>Welcome, {{ username }}!</h1>
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
    <h1>Welcome, Admin {{ username }}!</h1>
    <p>This is the admin page.</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""

# templates/403.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>403 Forbidden</title>
</head>
<body>
    <h1>403 Forbidden</h1>
    <p>You do not have permission to access this page.</p>
</body>
</html>
"""

# templates/404.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested page could not be found.</p>
</body>
</html>
"""

# templates/500.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>500 Internal Server Error</title>
</head>
<body>
    <h1>500 Internal Server Error</h1>
    <p>An unexpected error occurred on the server.</p>
</body>
</html>
"""

