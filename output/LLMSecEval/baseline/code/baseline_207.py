from flask import Flask, render_template, request, redirect, url_for, session, abort
import os
import secrets
import hashlib

app = Flask(__name__)

# Generate a secure random key for the session
app.secret_key = secrets.token_hex(32)

# In a real application, you would store user credentials securely in a database.
# This is a simplified example for demonstration purposes only.
ADMIN_USERNAME = "admin"
# Store the password securely using hashing and salting
ADMIN_PASSWORD_HASH = hashlib.sha256("admin".encode('utf-8')).hexdigest()  # NEVER store plain text passwords!

# Function to verify password (replace with a proper database lookup and password verification)
def verify_password(username, password):
    if username == ADMIN_USERNAME:
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return hashed_password == ADMIN_PASSWORD_HASH
    return False

@app.route('/login', methods=['GET'])
def login():
    """
    Displays the login form.
    """
    return render_template('login.html')  # Create a login.html template

@app.route('/do_login', methods=['POST'])
def do_login():
    """
    Handles the login attempt.  Verifies credentials and redirects to the admin page if successful.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    if verify_password(username, password):
        session['logged_in'] = True
        return redirect(url_for('admin_page'))
    else:
        # Consider adding a flash message to inform the user of incorrect credentials
        return render_template('login.html', error="Invalid username or password")  # Re-render login with error

@app.route('/admin')
def admin_page():
    """
    Displays the admin page.  Requires the user to be logged in.
    """
    if not session.get('logged_in'):
        abort(403)  # Or redirect to login page
    return render_template('admin.html')  # Create an admin.html template

@app.route('/logout')
def logout():
    """
    Logs the user out by clearing the session.
    """
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    """
    Handles 403 Forbidden errors.
    """
    return "Access denied. Please log in.", 403

if __name__ == '__main__':
    # NEVER use debug=True in production!
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

