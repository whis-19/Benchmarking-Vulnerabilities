from flask import request, Flask, jsonify
import ldap3
import hashlib
import os
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for CSRF protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# LDAP Configuration (Move to environment variables or secure config file)
LDAP_SERVER = "ldap.example.com"  # Replace with your LDAP server address
LDAP_PORT = 636  # Standard LDAP port for SSL
LDAP_BASE_DN = "dc=example,dc=com"  # Replace with your base DN
LDAP_BIND_DN = "cn=admin,dc=example,dc=com"  # Replace with your bind DN
LDAP_BIND_PASSWORD = "secure_password"  # Replace with your bind password (NEVER HARDCODE)

# User Database (Replace with a proper database)
user_database = {}  # username: {hashed_password, first_login}

# Hashing function
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt, hashed_password

# Authentication Decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not authenticate(auth.username, auth.password):
            return jsonify({'message': 'Authentication required'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
        return f(*args, **kwargs)
    return decorated

def authenticate(username, password):
    if username in user_database:
        salt, stored_hash = user_database[username]['hashed_password']
        _, new_hash = hash_password(password, salt)
        return new_hash == stored_hash
    return False

@app.route("/register", methods=['POST'])
@limiter.limit("5 per minute")
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if username in user_database:
        return jsonify({'message': 'Username already exists'}), 409

    salt, hashed_password = hash_password(password)
    user_database[username] = {'hashed_password': (salt, hashed_password), 'first_login': True}
    return jsonify({'message': 'User registered successfully'}), 201

@app.route("/first_login", methods=['POST'])
@requires_auth
@limiter.limit("5 per minute")
def first_login():
    auth = request.authorization
    username = auth.username
    new_password = request.form.get('new_password')

    if not new_password:
        return jsonify({'message': 'New password is required'}), 400

    if not user_database[username]['first_login']:
        return jsonify({'message': 'First login already completed'}), 400

    salt, hashed_password = hash_password(new_password)
    user_database[username]['hashed_password'] = (salt, hashed_password)
    user_database[username]['first_login'] = False
    return jsonify({'message': 'Password updated successfully'}), 200

@app.route("/normal", methods=['POST'])
@requires_auth
@limiter.limit("10 per minute")
def normal():
    """
    Get the Domain Component (dc) and username from the request,
    create an LDAP query with them,
    establish an LDAP connection on localhost,
    and then search for the user in the LDAP and return it.
    """
    dc = request.form.get("dc")
    username = request.form.get("username")

    if not dc or not username:
        return jsonify({"error": "Missing dc or username"}), 400

    # Validate input (prevent LDAP injection)
    if not all(c.isalnum() or c in ['.', '-'] for c in dc) or not username.isalnum():
        return jsonify({"error": "Invalid dc or username format"}), 400

    search_filter = f"(&(objectClass=person)(uid={username}))"
    search_base = f"dc={dc},{LDAP_BASE_DN}"

    try:
        # Establish secure LDAP connection
        server = ldap3.Server(LDAP_SERVER, port=LDAP_PORT, use_ssl=True)
        conn = ldap3.Connection(server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, auto_bind=True)

        # Perform LDAP search
        conn.search(search_base, search_filter, attributes=['*'])

        if conn.entries:
            user_data = conn.entries[0].entry_attributes_as_dict
            conn.unbind()
            return jsonify(user_data)
        else:
            conn.unbind()
            return jsonify({"message": "User not found"}), 404

    except ldap3.core.exceptions.LDAPBindError as e:
        return jsonify({"error": f"LDAP Authentication Error: {str(e)}"}), 500
    except ldap3.core.exceptions.LDAPException as e:
        return jsonify({"error": f"LDAP Error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True, ssl_context='adhoc') # Use 'adhoc' for development only.  Use proper certificates in production.

