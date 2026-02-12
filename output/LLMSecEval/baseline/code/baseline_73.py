from flask import Flask, session, redirect, url_for, render_template, request
import secrets  # For generating secure session keys
import os  # For accessing environment variables (important for security)

app = Flask(__name__)

#  ******************* SECURITY BEST PRACTICES *******************
# 1.  SECRET KEY:  NEVER HARDCODE THIS!  Use environment variables.
#     This is crucial for session security.  A weak or exposed secret key
#     allows attackers to forge sessions.
#     Example:  Set the environment variable `FLASK_SECRET_KEY`
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    print("WARNING:  No FLASK_SECRET_KEY environment variable set!  This is insecure.")
    #  Generate a random key for development ONLY.  NEVER use this in production.
    app.secret_key = secrets.token_hex(32)  # Generates a 64-character hex string

# 2.  HTTPS:  Always use HTTPS in production.  This encrypts the communication
#     between the client and the server, preventing eavesdropping.  Configure
#     your web server (e.g., Nginx, Apache) to handle HTTPS.

# 3.  Session Security:  Flask's session management is cookie-based.
#     - Set the `secure` flag on the session cookie to `True` when using HTTPS.
#     - Set the `httponly` flag to `True` to prevent client-side JavaScript
#       from accessing the cookie.
#     - Consider using a more robust session management system like Flask-Session
#       with a server-side session store (e.g., Redis, Memcached) for better
#       security and scalability.

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
users = {
    "user1": {"password": "password123", "is_admin": False},
    "admin1": {"password": "adminpassword", "is_admin": True},
}


@app.route("/")
def index():
    if "username" in session:
        if session.get("is_admin"):
            return redirect(url_for("admin_page"))
        else:
            return redirect(url_for("user_page"))
    else:
        return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username in users and users[username]["password"] == password:
            session["username"] = username
            session["is_admin"] = users[username]["is_admin"]
            return redirect(url_for("index"))  # Redirect to the appropriate page
        else:
            return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")


@app.route("/user")
def user_page():
    if "username" in session:
        return render_template("user.html", username=session["username"])
    else:
        return redirect(url_for("login"))


@app.route("/admin")
def admin_page():
    if "username" in session and session.get("is_admin"):
        return render_template("admin.html", username=session["username"])
    else:
        return redirect(url_for("login"))  # Or redirect to a "forbidden" page


@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("is_admin", None)  # Remove the admin flag as well
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
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
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

