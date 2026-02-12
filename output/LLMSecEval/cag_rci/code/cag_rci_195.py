from flask import Flask, render_template, request, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
from flask_bcrypt import Bcrypt  # Import Flask-Bcrypt
import secrets
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(32)  # Generate a CSRF secret key
# Store the secret key in an environment variable (e.g., export WTF_CSRF_SECRET_KEY=...)
# NEVER commit the secret key to your code repository!
app.config['SECRET_KEY'] = secrets.token_hex(32) # Required for Flask sessions
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)  # Initialize Flask-Bcrypt

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Example limits
    storage_uri="memory://"  # Use a persistent storage for production
)

# In a real application, you would store user data in a database.
users = {}  # Example: username -> hashed_password

# Example Form
class MyForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)]) #, Regexp(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+]).*$')])
    submit = SubmitField('Submit')

# Example Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Example Registration Form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)]) #, Regexp(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+]).*$')])
    submit = SubmitField('Register')

# Example of a login_required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in request.cookies:  # Check for a session cookie
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Hash the password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Store the username and hashed password in the database (or in our example, the 'users' dictionary)
        users[username] = hashed_password

        return redirect(url_for('login'))  # Redirect to the login page after successful registration

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Example rate limit for login
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Retrieve the hashed password from the database (or our 'users' dictionary)
        hashed_password = users.get(username)

        if hashed_password and bcrypt.check_password_hash(hashed_password, password):
            # Passwords match!  Log the user in.
            # In a real application, you would use Flask-Login to manage sessions.
            # For this example, we'll just set a cookie.
            resp = redirect(url_for('protected'))
            resp.set_cookie('username', username, httponly=True, secure=True)  # Store username in a cookie (for demonstration only)
            return resp
        else:
            # Invalid username or password
            return render_template('login.html', form=form, error="Invalid username or password")

    return render_template('login.html', form=form)

@app.route('/protected', methods=['GET', 'POST'])
@login_required
def protected():
    form = MyForm()
    if form.validate_on_submit():
        # Process the form data
        username = form.username.data
        # password = form.password.data  # No longer need the password here
        # return f"Form submitted with username: {username}" # Vulnerable to XSS
        return render_template('protected_success.html', username=username) # Safer approach
    return render_template('protected.html', form=form)

@app.route('/logout')
def logout():
    resp = redirect(url_for('login'))
    resp.set_cookie('username', '', expires=0)  # Delete the cookie
    return resp

@app.route('/')
def index():
    return "Hello, World!  Try /login or /register"

if __name__ == '__main__':
    app.run(debug=True)

