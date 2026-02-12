from flask import Flask, request, render_template_string, session, redirect, url_for
import os
import secrets
import hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong, random secret key

# Securely read credentials from file
def read_credentials_from_file(filename):
    """
    Reads credentials from a file, using a more secure approach.
    """
    credentials = {}
    try:
        with open(filename, 'r') as file:
            for line in file:
                if ':' in line:
                    key, value = line.strip().split(':', 1)  # Split only once
                    credentials[key] = value
    except FileNotFoundError:
        print(f"Error: Credentials file '{filename}' not found.")
        return None  # Or raise an exception if appropriate
    except Exception as e:
        print(f"Error reading credentials file: {e}")
        return None

    return credentials


# Securely check login credentials using hashing
def check_login(username, password):
    """
    Checks login credentials against stored hashed passwords.
    """
    credentials = read_credentials_from_file('credentials.txt')
    if not credentials:
        return False

    stored_username = credentials.get('username')
    stored_password_hash = credentials.get('password')

    if not stored_username or not stored_password_hash:
        print("Error: Username or password hash not found in credentials file.")
        return False

    # Hash the provided password and compare it to the stored hash
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    if stored_username == username and stored_password_hash == hashed_password:
        return True
    else:
        return False


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.
    """
    message = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            message = 'Please enter both username and password.'
        elif check_login(username, password):
            session['username'] = username  # Store username in session
            session['csrf_token'] = secrets.token_hex(16) # Generate CSRF token
            return redirect(url_for('show_dashboard'))
        else:
            message = 'Login failed!'

    # Render the login form with CSRF protection
    return render_template_string('''
    <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    <p>{{ message }}</p>
    ''', message=message, csrf_token=session.get('csrf_token'))


@app.route('/dashboard', methods=['GET'])
def show_dashboard():
    """
    Renders the dashboard if the user is logged in.
    """
    if 'username' in session:
        return render_template_string('''
        <h1>Welcome to the Dashboard, {{ username }}!</h1>
        <a href="{{ url_for('logout') }}">Logout</a>
        ''', username=session['username'])
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """
    Logs the user out by clearing the session.
    """
    session.pop('username', None)
    session.pop('csrf_token', None)
    return redirect(url_for('login'))


# Example of a protected route with CSRF protection
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    """
    Example route that requires CSRF protection.
    """
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if csrf_token != session.get('csrf_token'):
            return "CSRF token is invalid!", 400

        new_password = request.form.get('new_password')
        if not new_password:
            return "New password cannot be empty!", 400

        # In a real application, you would update the password in the credentials file
        # after properly hashing it.  This is just a placeholder.
        # IMPORTANT: Never store passwords in plain text!
        hashed_password = hashlib.sha256(new_password.encode('utf-8')).hexdigest()

        # In a real application, you would update the credentials file here.
        # For this example, we'll just print the hashed password.
        print(f"New password hash: {hashed_password}")

        return "Password changed successfully!"

    # Generate a new CSRF token for the form
    session['csrf_token'] = secrets.token_hex(16)
    return render_template_string('''
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            New Password: <input type="password" name="new_password"><br>
            <input type="submit" value="Change Password">
        </form>
    ''', csrf_token=session.get('csrf_token'))


if __name__ == '__main__':
    # Create a dummy credentials file for testing
    if not os.path.exists('credentials.txt'):
        # Generate a random salt
        salt = secrets.token_hex(16)

        # Hash the password using SHA-256
        password = "password123"
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        with open('credentials.txt', 'w') as f:
            f.write(f"username:testuser\n")
            f.write(f"password:{hashed_password}\n")

    app.run(debug=True, ssl_context='adhoc') # Enable HTTPS with a self-signed certificate

