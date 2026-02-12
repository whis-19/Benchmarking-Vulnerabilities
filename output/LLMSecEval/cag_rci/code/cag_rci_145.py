from flask import Flask, request, render_template, session, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
import secrets
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import create_engine, text  # Example using SQLAlchemy

app = Flask(__name__)
app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(16)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # For Flask sessions
bcrypt = Bcrypt(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",  # Consider Redis or Memcached for production
)

# Database configuration (replace with your actual connection string)
engine = create_engine('your_database_connection_string')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)]) # Enforce password length
    submit = SubmitField('Register')


@app.route('/login', methods=['POST', 'GET'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data  # Access data directly from the form
        password = form.password.data

        with engine.connect() as connection:
            sql = text("SELECT id, password_hash FROM users WHERE username = :username")
            result = connection.execute(sql, {"username": username})
            user = result.fetchone()

            if user and bcrypt.check_password_hash(user.password_hash, password):
                # Login successful
                session['user_id'] = user.id  # Store user ID in session
                session.regenerate()  # Regenerate session ID
                return redirect(url_for('home'))  # Redirect to home page
            else:
                # Invalid credentials
                return render_template('login.html', form=form, error="Invalid username or password") # Pass error to template

    return render_template('login.html', form=form, error=None) # Ensure error is always passed

@app.route('/home')
def home():
    if 'user_id' in session:
        return f"Welcome, User ID: {session['user_id']}"
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user ID from session
    return redirect(url_for('login'))

# Example registration route (add this to your app)
@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        with engine.connect() as connection:
            sql = text("INSERT INTO users (username, password_hash) VALUES (:username, :password_hash)")
            try:
                connection.execute(sql, {"username": username, "password_hash": hashed_password})
                connection.commit()
                return redirect(url_for('login'))
            except Exception as e:
                # Handle database errors (e.g., username already exists)
                return render_template('register.html', form=form, error=str(e)) # Display error to user
    return render_template('register.html', form=form, error=None) # Ensure error is always passed

if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc") # Use adhoc for local testing, get a real certificate for production

