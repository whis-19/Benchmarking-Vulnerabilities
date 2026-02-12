from functools import wraps
from flask import Flask, flash, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_required, current_user, login_user
from werkzeug.security import generate_password_hash, check_password_hash
# Assuming you're using SQLAlchemy
from flask_sqlalchemy import SQLAlchemy
import os
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Replace with a strong, persistent secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Replace with your database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Reduces overhead
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if not authenticated

# CSRF Protection (using Flask-WTF) - Install: pip install flask-wtf
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24) # CSRF Secret Key

# Session Cookie Configuration (Important for Security)
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Mitigate CSRF (Strict is even stronger, but can break some legitimate use cases)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)  # Store password hash
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Define roles and their associated permissions (Consider storing in DB)
ROLES = {
    'user': ['view_profile', 'buy_stock'],
    'admin': ['view_profile', 'buy_stock', 'manage_users', 'view_admin_panel']
}

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated and permission in ROLES.get(current_user.role, []):
                return f(*args, **kwargs)
            else:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('home'))
        return decorated_function
    return decorator

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            if not is_safe_url(next_page):
                return abort(400)  # Or redirect to a default page
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger') # Generic error message
    return render_template('login.html', title='Login', form=form)

@app.route("/")
def home():
    return "Home Page"

@app.route("/admin")
@login_required
@permission_required('view_admin_panel')
def admin():
    # Security: Only accessible to users with the 'view_admin_panel' permission
    return "Admin Panel"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables within the application context
    app.run(debug=True)

