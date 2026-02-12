from flask import Flask, request, render_template
import os
import secrets
import hashlib
from cryptography.fernet import Fernet

app = Flask(__name__)

#  IMPORTANT:  NEVER store sensitive data like this in a real application.
#  This is for demonstration purposes ONLY.  In a real application, you would
#  use a secure database with proper access controls and encryption.
user_data = {
    "username": "testuser",
    "email": "test@example.com",
    "ssn_last_4": "1234"  # DO NOT STORE FULL SSN
}

# Encryption Key (Ideally, this should be stored securely, e.g., in a vault)
#  NEVER hardcode encryption keys in production code.  Use environment variables
#  or a secure key management system.
encryption_key = os.environ.get("ENCRYPTION_KEY")
if not encryption_key:
    print("WARNING: ENCRYPTION_KEY not found in environment. Generating a new key.  This is NOT secure for production.")
    encryption_key = Fernet.generate_key().decode()
    print(f"Generated key: {encryption_key}") # Remove this in production!
    #  In a real application, store this key securely.
    #  For example:  os.environ["ENCRYPTION_KEY"] = encryption_key
    #  Then restart the application.
    
fernet = Fernet(encryption_key.encode())


# Function to encrypt data
def encrypt_data(data):
    return fernet.encrypt(data.encode()).decode()

# Function to decrypt data
def decrypt_data(data):
    return fernet.decrypt(data.encode()).decode()


#  CSRF Protection (Important for preventing Cross-Site Request Forgery attacks)
#  Generate a secret key for CSRF protection.  This should be a long, random string.
app.secret_key = os.urandom(24)  # Use os.urandom for cryptographically secure randomness


# Rate Limiting (Basic example - consider using a more robust library)
request_counts = {}
RATE_LIMIT = 5  # Maximum requests per minute
RATE_LIMIT_WINDOW = 60  # Seconds

def rate_limit_exceeded(ip_address):
    """Checks if the rate limit has been exceeded for a given IP address."""
    import time
    now = time.time()
    if ip_address not in request_counts:
        request_counts[ip_address] = []
    
    # Remove requests older than the rate limit window
    request_counts[ip_address] = [ts for ts in request_counts[ip_address] if now - ts < RATE_LIMIT_WINDOW]
    
    if len(request_counts[ip_address]) >= RATE_LIMIT:
        return True
    else:
        request_counts[ip_address].append(now)
        return False


@app.route('/info')
def info():
    ip_address = request.remote_addr  # Get the user's IP address

    if rate_limit_exceeded(ip_address):
        return "Rate limit exceeded. Please try again later.", 429  # HTTP 429 Too Many Requests

    #  Retrieve user data (from a database in a real application)
    username = user_data["username"]
    email = user_data["email"]

    #  Encrypt the last 4 digits of the SSN before displaying it.
    encrypted_ssn_last_4 = encrypt_data(user_data["ssn_last_4"])

    #  Render the template with the data.  Use proper HTML escaping to prevent XSS.
    return render_template('info.html', username=username, email=email, ssn_last_4=encrypted_ssn_last_4)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    #  NEVER run in debug mode in production.  It exposes sensitive information.
    #  Use a production WSGI server like Gunicorn or uWSGI.
    app.run(debug=False, host='0.0.0.0', port=5000)

