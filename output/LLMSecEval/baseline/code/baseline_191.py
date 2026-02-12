from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import Form, StringField, PasswordField, validators
import sqlite3  # Or your database library (e.g., SQLAlchemy, psycopg2)
import bcrypt
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Change this to a strong, random key!
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True

# Database setup (SQLite example)
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def create_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

create_table()  # Create the table if it doesn't exist

# Registration Form
class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))  # Redirect to login after registration
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('register.html', form=form, error="Username already exists")

    return render_template('register.html', form=form)


# Login Form (Simple example, consider using WTForms for more robust validation)
class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired()])


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            hashed_password = result['password_hash']  # Access by column name
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                session['username'] = username  # Store username in session
                return redirect(url_for('home'))
            else:
                return render_template('login.html', error='Invalid credentials', form=form)
        else:
            return render_template('login.html', error='Invalid credentials', form=form)

    return render_template('login.html', form=form)


@app.route('/home')
def home():
    if 'username' in session:
        return f"Logged in as {session['username']}! <a href='/logout'>Logout</a>"
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

@app.route('/')
def index():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

