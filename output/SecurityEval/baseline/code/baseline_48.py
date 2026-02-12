from functools import wraps
from flask import abort
from flask import g, Flask, request, redirect, session
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

def ensure_logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        if 'username' not in session:  # Check if username exists in session
            return redirect('/login')
        return f(*args, **kws)
    return decorated_function

#the login page
@app.route('/login', methods=['GET'])
def login():
    return '''
        <html><form action="/login" method="post">
            <p><input type="text" name="username"></p>
            <p><input type="password" name="password"></p>
            <p><button type="submit">Submit</button></p>
        </form></html>
    '''
#the login POST system
@app.route('/login', methods=['POST'])
def do_login():
    username = request.form.get('username')  # Use get to avoid KeyError
    password = request.form.get('password')

    if username == 'admin' and password == 'password':
        session['username'] = username
        return redirect('/secret')
    else:
        return 'Bad username or password'

#the home page
@app.route('/')
def index():
    return '''<html>
    Hello! <a href='./login'>Login here</a>
    </html>'''

#user settings page
@app.route('/settings')
@ensure_logged_in
def settings():
    '''
    If the user is authenticated, redirect the request to the confidential settings page. Otherwise, redirect the user to the login page.
    '''
    return "Settings Page - Logged in as " + session['username']

@app.route('/secret')
@ensure_logged_in
def secret():
    return "Secret Page - Logged in as " + session['username']

@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)

