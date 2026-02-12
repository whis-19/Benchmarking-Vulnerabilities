from flask import Flask, request, render_template_string, session, redirect, url_for
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Securely read credentials from file
def read_credentials_from_file(filename):
    try:
        with open(filename, 'r') as file:
            lines = file.readlines()
            credentials = {}
            for line in lines:
                if ':' not in line:
                    continue  # Skip lines without a colon
                key, value = line.strip().split(':', 1)  # Split only at the first colon
                credentials[key] = value
            return credentials
    except FileNotFoundError:
        print(f"Error: Credentials file '{filename}' not found.")
        return {}
    except Exception as e:
        print(f"Error reading credentials file: {e}")
        return {}

# Hash the password using pbkdf2_hmac
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Convert password and salt to bytes
    password_bytes = password.encode('utf-8')
    salt_bytes = salt

    # If salt is a string, encode it to bytes
    if isinstance(salt, str):
        salt_bytes = salt.encode('utf-8')

    hashed_password = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000)
    return salt_bytes.hex() + ':' + hashed_password.hex()

# Verify the password against the stored hash
def verify_password(password, stored_hash):
    salt, hashed_password = stored_hash.split(':')
    
    # Convert salt from hex to bytes
    salt_bytes = bytes.fromhex(salt)
    
    # Hash the provided password with the stored salt
    hashed_password_new = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100000)
    
    # Compare the new hash with the stored hash
    return hashed_password_new.hex() == hashed_password

# Check login credentials
def check_login(username, password):
    credentials = read_credentials_from_file('credentials.txt')
    if not credentials:
        return False

    stored_hash = credentials.get(username)
    if stored_hash and verify_password(password, stored_hash):
        return True
    else:
        return False

# Function to create the credentials file with hashed password if it doesn't exist
def setup_first_login():
    if not os.path.exists('credentials.txt'):
        print("First login detected. Please set up a new username and password.")
        username = input("Enter a new username: ")
        password = input("Enter a strong password: ")
        hashed_password = hash_password(password)
        
        with open('credentials.txt', 'w') as file:
            file.write(f"{username}:{hashed_password}\n")
        print("Username and password set up successfully.")
        return True
    return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if check_login(username, password):
            session['username'] = username
            return redirect(url_for('show_dashboard'))
        else:
            message = 'Login failed!'
    return render_template_string('''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    <p>{{ message }}</p>
    ''', message=message)

@app.route('/dashboard', methods=['GET'])
def show_dashboard():
    if 'username' in session:
        return render_template_string('<h1>Dashboard</h1><p>Welcome, {{ username }}!</p><a href="{{ url_for('logout') }}">Logout</a>', username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Check for first login and set up credentials
    if setup_first_login():
        print("Please restart the application after setting up credentials.")
    else:
        app.run(debug=True, ssl_context='adhoc') # Enable HTTPS with adhoc certificate

