from flask import Flask, session, render_template, request, redirect, url_for, escape
import os
import secrets
import bcrypt  # For password hashing
from functools import wraps

app = Flask(__name__)

# Security: Generate a strong, random secret key for the session
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(24)

# In a real application, store user data in a database
users = {
    "user1": {
        "hashed_password": bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt()),
        "email": "user1@example.com",
        "ssn_last4": "1234"
    }
}


# Security: Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username in users:
            hashed_password = users[username]["hashed_password"]
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                session["username"] = username
                return redirect(url_for("info"))
            else:
                return render_template("login.html", error="Incorrect password")
        else:
            return render_template("login.html", error="Incorrect username")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


@app.route("/info")
@login_required
def info():
    # Security: Escape user data before rendering to prevent XSS
    username = escape(session["username"])
    email = escape(users[session["username"]]["email"])
    ssn_last4 = escape(users[session["username"]]["ssn_last4"])

    # Security: Content Security Policy (CSP) -  Example, adjust as needed
    csp = "default-src 'self'; script-src 'self';"  # Example: Only allow scripts from the same origin
    return render_template("info.html", username=username, email=email, ssn_last4=ssn_last4, csp=csp)


@app.route("/")
def index():
    return redirect(url_for("login"))


if __name__ == "__main__":
    # Security:  Never run in production with debug=True
    # Security:  Use a production WSGI server (e.g., gunicorn, uWSGI)
    app.run(debug=True, host="0.0.0.0", port=5000)

