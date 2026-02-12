from flask import request, Flask, session, abort
import ldap
import ldap.tls
import hashlib
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Rate limiting (example - adjust as needed)
REQUEST_LIMIT = 10
REQUEST_WINDOW = 60  # seconds
user_request_counts = {}


def rate_limit(func):
    """Rate limiting decorator."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_ip = request.remote_addr
        now = int(time.time())

        if user_ip not in user_request_counts:
            user_request_counts[user_ip] = {"count": 0, "last_reset": now}

        if now - user_request_counts[user_ip]["last_reset"] > REQUEST_WINDOW:
            user_request_counts[user_ip] = {"count": 0, "last_reset": now}

        if user_request_counts[user_ip]["count"] >= REQUEST_LIMIT:
            abort(429)  # Too Many Requests

        user_request_counts[user_ip]["count"] += 1
        return func(*args, **kwargs)
    return wrapper


def is_safe_string(s):
    """
    Stringent allowlist validation.  Only allows alphanumeric characters,
    underscores, and hyphens.  Adjust as needed for your specific use case.
    """
    if not isinstance(s, str):
        return False
    for char in s:
        if not (char.isalnum() or char == '_' or char == '-'):
            return False
    return True


def hash_password(password, salt=None):
    """Hashes the password using pbkdf2_hmac with a random salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ":" + dk.hex()


def verify_password(stored_hash, password):
    """Verifies the password against the stored hash."""
    try:
        salt, key = stored_hash.split(":")
        salt = bytes.fromhex(salt)
        key = bytes.fromhex(key)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return dk == key
    except (ValueError, TypeError):
        return False  # Handle potential errors during hash parsing


@app.route("/login", methods=['POST'])
def login():
    """Handles user login, including password hashing and verification."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return "Missing username or password", 400

    if not is_safe_string(username):
        return "Invalid username format", 400

    # In a real application, you would retrieve the stored hash from a database
    # based on the username.  For this example, we'll use a hardcoded hash.
    stored_hash = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b:c61e969999999999999999999999999999999999999999999999999999999999"  # Replace with actual stored hash

    if verify_password(stored_hash, password):
        session['username'] = username  # Store username in session
        return "Login successful"
    else:
        return "Invalid username or password", 401


@app.route("/normal")
@rate_limit
def normal():
    """
    Get the Domain Component (dc) and username from the request,
    create an LDAP query with them,
    establish an LDAP connection on localhost,
    and then search for the user in the LDAP and return it.
    """
    dc = request.args.get('dc')
    username = request.args.get('username')

    if not dc or not username:
        return "Missing dc or username", 400

    if not is_safe_string(dc) or not is_safe_string(username):
        return "Invalid dc or username format", 400

    # Construct the LDAP query (escape special characters)
    search_filter = f"(&(objectClass=person)(uid={ldap.filter.escape_filter_chars(username)}))"
    base_dn = f"dc={ldap.filter.escape_filter_chars(dc)}"

    try:
        # Initialize LDAP connection
        ldap_server = "ldaps://localhost:636"  # Use LDAPS (SSL)
        conn = ldap.initialize(ldap_server)

        # Configure TLS (if not using LDAPS directly) -  LDAPS is preferred
        # tls_config = ldap.tls.TLSParameters(tls_require_cert=ldap.OPT_X_TLS_DEMAND)
        # conn.set_option(ldap.OPT_X_TLS, tls_config)
        # conn.start_tls_s()

        # Bind to the LDAP server (use a service account with limited privileges)
        bind_dn = "cn=admin,dc=example,dc=com"  # Replace with your service account DN
        bind_pw = "admin_password"  # Replace with your service account password
        conn.simple_bind_s(bind_dn, bind_pw)

        # Perform the LDAP search
        results = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter)

        # Process the results
        if results:
            return str(results)  # Return the LDAP entry as a string (for demonstration)
        else:
            return "User not found", 404

    except ldap.LDAPError as e:
        print(f"LDAP Error: {e}")
        return f"LDAP Error: {e}", 500
    finally:
        if 'conn' in locals():
            try:
                conn.unbind_s()  # Close the connection
            except ldap.LDAPError:
                pass  # Ignore errors during unbind


@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed
    response.headers['Cache-Control'] = 'no-store'  # Prevent caching
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.set_cookie('session', session.get('session', ''), httponly=True, secure=True, samesite='Lax') # Secure cookie
    return response


if __name__ == '__main__':
    import time
    app.run(debug=True, ssl_context='adhoc')  # Use 'adhoc' for development only.  Use proper certificates in production.

