from flask import request, Flask, jsonify, session
import ldap3
import os
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt  # For password hashing
import logging
from ldap3.utils.conv import escape_filter_chars
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get("REDIS_URL", "redis://localhost:6379")  # Use Redis for persistent storage, fallback to localhost
)

# Configuration (from environment variables)
LDAP_SERVER = os.environ.get("LDAP_SERVER", "localhost")
LDAP_PORT = int(os.environ.get("LDAP_PORT", 636))
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=example,dc=com")
LDAP_ADMIN_USER = os.environ.get("LDAP_ADMIN_USER", "cn=admin,dc=example,dc=com")
LDAP_ADMIN_PASSWORD = os.environ.get("LDAP_ADMIN_PASSWORD")  # Securely stored in environment
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24).hex())  # Generate a random secret key
app.config['SECRET_KEY'] = SECRET_KEY

# Session Security Configuration
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF


# Authentication decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not authenticate(auth.username, auth.password):
            return jsonify({'message': 'Authentication required'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
        return f(*args, **kwargs)
    return decorated

def authenticate(username, password):
    """Authenticates the user against LDAP by attempting to bind."""
    try:
        server = ldap3.Server(LDAP_SERVER, port=LDAP_PORT, use_ssl=True)
        conn = ldap3.Connection(server, user=f"uid={username},{LDAP_BASE_DN}", password=password, auto_bind=False) # Bind as the user
        if conn.bind():
            session['username'] = username  # Store username in session
            conn.unbind()
            return True
        else:
            logger.warning(f"LDAP Authentication Failed for user: {username}")
            if 'conn' in locals() and conn:
                conn.unbind()
            return False
    except ldap3.core.exceptions.LDAPBindError as e:
        logger.error(f"LDAP Authentication Failed: {e}")
        return False
    except Exception as e:
        logger.exception(f"LDAP Error during authentication: {e}") # Log the full exception
        return False
    finally:
        if 'conn' in locals() and conn and conn.bound:
            conn.unbind()

def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')  # Store as string

def verify_password(password, hashed_password):
    """Verifies the password against the stored hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

@app.route("/normal")
@requires_auth
@limiter.limit("5/minute")  # Rate limit this endpoint
def normal():
    '''
    Get the Domain Component (dc) and username from the request,
    create an LDAP query with them,
    establish an LDAP connection on localhost,
    and then search for the user in the LDAP and return it.
    '''
    dc = request.args.get('dc')
    username = request.args.get('username')

    if not dc or not username:
        return jsonify({"error": "Missing dc or username parameters"}), 400

    # Input validation: Sanitize inputs to prevent LDAP injection
    dc = escape_filter_chars(dc)
    username = escape_filter_chars(username)

    search_filter = f'(&(objectClass=person)(uid={username})(dc={dc}))'  # Example filter

    try:
        # Establish LDAP connection with SSL and authentication
        server = ldap3.Server(LDAP_SERVER, port=LDAP_PORT, use_ssl=True)
        conn = ldap3.Connection(server, user=LDAP_ADMIN_USER, password=LDAP_ADMIN_PASSWORD, auto_bind=True)

        # Search for the user
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=['uid', 'cn', 'sn', 'mail']  # Specify attributes you need, avoid '*' in production
        )

        if conn.entries:
            user_data = conn.entries[0].entry_attributes_as_dict
            return jsonify(user_data)
        else:
            return jsonify({"message": "User not found"}), 404

    except ldap3.core.exceptions.LDAPException as e:
        logger.exception(f"LDAP Error: {e}")
        return jsonify({"error": "An error occurred while processing your request"}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.unbind()

@app.route("/register", methods=['POST'])
def register():
    """
    Registers a new user in LDAP.
    """
    username = request.form.get('username')
    password = request.form.get('password')
    dc = request.form.get('dc')

    if not username or not password or not dc:
        return jsonify({"error": "Missing username, password, or dc parameters"}), 400

    # Sanitize inputs to prevent LDAP injection
    username = escape_filter_chars(username)
    dc = escape_filter_chars(dc)

    # Password Complexity Check
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    # Add more complexity checks as needed (e.g., special characters, numbers)


    # Hash the password
    hashed_password = hash_password(password)

    # Construct the user's DN
    user_dn = f"uid={username},dc={dc},{LDAP_BASE_DN}"

    # Construct the attributes for the new user
    attributes = {
        'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
        'uid': [username],
        'cn': [username],
        'sn': [username],  # Assuming surname is the same as username
        'userPassword': [hashed_password]  # Store the hashed password
    }

    try:
        # Establish LDAP connection with SSL and authentication
        server = ldap3.Server(LDAP_SERVER, port=LDAP_PORT, use_ssl=True)
        conn = ldap3.Connection(server, user=LDAP_ADMIN_USER, password=LDAP_ADMIN_PASSWORD, auto_bind=True)

        # Add the new user to LDAP
        conn.add(user_dn, attributes)

        if conn.result['result'] == 0:
            return jsonify({"message": "User registered successfully"}), 201
        else:
            logger.error(f"Failed to register user: {conn.result['message']}")
            return jsonify({"error": "Failed to register user"}), 500

    except ldap3.core.exceptions.LDAPException as e:
        logger.exception(f"LDAP Error: {e}")
        return jsonify({"error": "An error occurred while processing your request"}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.unbind()

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Use 'adhoc' for development only.  Use proper certificates in production.

