from flask import Flask, session, request, jsonify
import os
import secrets
from functools import wraps

app = Flask(__name__)

# Generate a secure random key for the session
app.secret_key = secrets.token_hex(32)  # Use a strong, random key

# Security Best Practices:
# 1.  HTTPS:  **MANDATORY**  Deploy this application behind HTTPS.  Never transmit sensitive data (like SSN) over HTTP.
# 2.  Input Validation:  This example *intentionally* lacks input validation to highlight the vulnerability.  In a real application, *always* validate and sanitize all user inputs.
# 3.  Rate Limiting: Implement rate limiting to prevent brute-force attacks.
# 4.  Content Security Policy (CSP):  Use CSP to prevent XSS attacks.
# 5.  Regular Security Audits:  Conduct regular security audits and penetration testing.
# 6.  Principle of Least Privilege:  Ensure the application runs with the minimum necessary privileges.
# 7.  Consider alternative storage: Storing sensitive data like SSN in session is highly discouraged. Consider using a database with proper encryption and access controls.

# Authentication Decorator (Example - Replace with a robust authentication system)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')  # NEVER store passwords in plain text!

    # In a real application, you would verify the username and password against a secure database.
    # This is a placeholder for demonstration purposes ONLY.
    if username == "testuser" and password == "password":
        session['username'] = username
        # Simulate setting other user data (INSECURE - DO NOT DO THIS IN REALITY)
        session['email'] = "test@example.com"
        session['ssn'] = "123-45-6789"  # NEVER store SSN in session!
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/info', methods=['GET'])
@login_required
def info():
    """
    Returns user information (username, email, SSN) stored in the session.

    WARNING: Storing sensitive information like SSN in the session is extremely insecure.
             This is for demonstration purposes ONLY and should NEVER be done in a real application.
    """
    username = session.get('username', 'N/A')
    email = session.get('email', 'N/A')
    ssn = session.get('ssn', 'N/A')  # VERY INSECURE!

    # IMPORTANT SECURITY NOTE:
    # Returning the SSN in this way is a major security vulnerability.
    # In a real application, you should NEVER expose sensitive information like SSN.
    # Instead, consider using a secure database with proper access controls and encryption.
    # Only return the information that is absolutely necessary for the user to see.

    return jsonify({
        'username': username,
        'email': email,
        'ssn': ssn  # DO NOT DO THIS IN PRODUCTION
    })


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    session.pop('email', None)
    session.pop('ssn', None)
    return jsonify({'message': 'Logged out'})


if __name__ == '__main__':
    # NEVER run this in production without a proper WSGI server (e.g., Gunicorn, uWSGI)
    # and HTTPS enabled.
    app.run(debug=True, host='0.0.0.0', port=5000)

