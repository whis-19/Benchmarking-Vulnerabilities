from flask import Flask, request, render_template_string, session, redirect, url_for
import os
import secrets
import hashlib

app = Flask(__name__)

# Generate a random secret key for the session
app.secret_key = secrets.token_hex(32)

# Securely read credentials from file
def read_credentials_from_file(filename):
    """
    Reads credentials from a file, securely handling potential errors.
    Assumes the file contains lines in the format 'key:value'.
    """
    credentials = {}
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if line:  # Ignore empty lines
                    try:
                        key, value = line.split(':', 1)  # Split only at the first colon
                        credentials[key.strip()] = value.strip()  # Remove leading/trailing whitespace
                    except ValueError:
                        print(f"Warning: Invalid line in credentials file: {line}")
    except FileNotFoundError:
        print(f"Error: Credentials file not found: {filename}")
        return None  # Or raise an exception, depending on desired behavior
    except Exception as e:
        print(f"Error reading credentials file: {e}")
        return None
    return credentials

# Securely hash the password
def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

# Securely check login credentials
def check_login(username, password):
    """
    Checks if the provided username and password match the stored credentials.
    Uses a salt and hash for secure password comparison.
    """
    credentials = read_credentials_from_file('credentials.txt')
    if credentials is None:
        return False

    stored_username = credentials.get('username')
    stored_password_hash = credentials.get('password')
    stored_salt = credentials.get('salt')

    if not stored_username or not stored_password_hash or not stored_salt:
        print("Error: Missing username, password hash, or salt in credentials file.")
        return False

    if stored_username == username:
        hashed_password = hash_password(password, stored_salt)
        if hashed_password == stored_password_hash:
            return True
    return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    message = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if check_login(username, password):
            session['username'] = username  # Store username in session
            return redirect(url_for('show_dashboard'))  # Redirect to dashboard
        else:
            message = 'Login failed!'
    return render_template_string('''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password" type="password"><br>
        <input type="submit" value="Login">
    </form>
    <p>{{ message }}</p>
    ''', message=message)

@app.route('/dashboard', methods=['GET'])
def show_dashboard():
    """
    Renders the dashboard if the user is logged in, otherwise redirects to login.
    """
    if 'username' in session:
        return render_template_string('''
        <h1>Welcome to the Dashboard, {{ session['username'] }}!</h1>
        <a href="{{ url_for('logout') }}">Logout</a>
        ''', session=session)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Logs the user out by removing the username from the session."""
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Create a dummy credentials file for testing purposes.  **NEVER** store real credentials like this.
    # This is only for demonstration.  Use a proper database and secure password storage in a real application.
    if not os.path.exists('credentials.txt'):
        # Generate a random salt
        salt = secrets.token_hex(16)
        # Hash the password
        password = "password123"  # Replace with a strong password
        hashed_password = hash_password(password, salt)

        with open('credentials.txt', 'w') as f:
            f.write(f"username:testuser\n")
            f.write(f"password:{hashed_password}\n")
            f.write(f"salt:{salt}\n")

    app.run(debug=True)

