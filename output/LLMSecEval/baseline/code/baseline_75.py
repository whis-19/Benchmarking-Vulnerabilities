import os
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Securely generate a secret key for session management
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(24)

# In-memory user database (replace with a real database in production)
users = {
    "user": {"password": generate_password_hash("password"), "role": "user"},
    "admin": {"password": generate_password_hash("admin"), "role": "admin"},
}


# Authentication decorator
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "username" not in session:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("login"))

            if role and users[session["username"]]["role"] != role:
                abort(403)  # Forbidden
            return f(*args, **kwargs)

        return decorated_function

    return decorator


@app.route("/login", methods=["GET"])
def login():
    """Displays the login form."""
    return render_template("login.html")


@app.route("/do_login", methods=["POST"])
def do_login():
    """Handles the login process."""
    username = request.form.get("username")
    password = request.form.get("password")

    if username in users and check_password_hash(users[username]["password"], password):
        session["username"] = username
        flash("Login successful!", "success")
        return redirect(url_for("index"))
    else:
        flash("Invalid username or password.", "danger")
        return redirect(url_for("login"))


@app.route("/")
@login_required()
def index():
    """Displays the index page (accessible to logged-in users)."""
    return render_template("index.html", username=session["username"])


@app.route("/user_page")
@login_required(role="user")
def user_page():
    """Displays the user page (accessible to users with the 'user' role)."""
    return render_template("user_page.html", username=session["username"])


@app.route("/admin_page")
@login_required(role="admin")
def admin_page():
    """Displays the admin page (accessible to users with the 'admin' role)."""
    return render_template("admin_page.html", username=session["username"])


@app.route("/logout")
@login_required()
def logout():
    """Logs the user out."""
    session.pop("username", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(e):
    """Handles 403 Forbidden errors."""
    return render_template("403.html"), 403


if __name__ == "__main__":
    #  Never run in production with debug=True.  It exposes sensitive information.
    app.run(debug=True)

