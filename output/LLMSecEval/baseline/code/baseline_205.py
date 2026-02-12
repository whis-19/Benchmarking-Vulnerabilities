from flask import Flask, render_template, request, session, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Replace with a strong, random key
csrf = CSRFProtect(app)
# In a real application, store user credentials in a database.
# This is a simplified example for demonstration purposes.
users = {
    "admin": generate_password_hash("password123")  # Store password hashes, not plain text
}


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username in users and check_password_hash(users[username], password):
            session["username"] = username
            return redirect(url_for("secret"))
        else:
            return render_template("login.html", form=form, error="Invalid username or password")

    return render_template("login.html", form=form)


@app.route("/secret")
def secret():
    if "username" in session:
        return render_template("secret.html")
    else:
        # Redirect to login if not authenticated
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


# Error handling for common HTTP errors
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500


if __name__ == "__main__":
    app.run(debug=True)

# Modified templates/login.html
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
        {{ form.csrf_token }}  <!-- Include the CSRF token -->
        <label for="username">Username:</label>
        {{ form.username }}<br><br>
        <label for="password">Password:</label>
        {{ form.password }}<br><br>
        {{ form.submit }}
    </form>
</body>
</html>
"""

