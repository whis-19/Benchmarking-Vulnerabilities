from flask import request, Flask, jsonify
import ldap3
import os
import hashlib
import secrets
import base64

app = Flask(__name__)

# Configuration (ideally, load from environment variables or a secure config file)
LDAP_SERVER = os.environ.get("LDAP_SERVER", "localhost")  # e.g., "ldap.example.com"
LDAP_PORT = int(os.environ.get("LDAP_PORT", "636"))  # Standard LDAP port is 389, LDAPS is 636
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=example,dc=com")  # e.g., "dc=example,dc=com"
LDAP_USER = os.environ.get("LDAP_USER", "cn=admin,dc=example,dc=com") # e.g., "cn=admin,dc=example,dc=com"
LDAP_PASSWORD = os.environ.get("LDAP_PASSWORD", "admin") # NEVER hardcode in production!
SALT_LENGTH = 16  # Length of the salt for password hashing

def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hashes the password using PBKDF2-HMAC with a randomly generated salt."""
    if salt is None:
        salt = secrets.token_bytes(SALT_LENGTH)
    
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Iterations - adjust based on security needs
    )
    return hashed_password, salt

def verify_password(password: str, hashed_password: bytes, salt: bytes) -> bool:
    """Verifies the password against the stored hash and salt."""
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return secrets.compare_digest(new_hash, hashed_password)


@app.route("/normal")
def normal():
    """
    Get the Domain Component (dc) and username from the request,
    create an LDAP query with them,
    establish an LDAP connection,
    and then search for the user in the LDAP and return it.
    """
    username = request.args.get("username")
    dc = request.args.get("dc")

    if not username or not dc:
        return jsonify({"error": "Missing username or dc parameter"}), 400

    # Input validation:  Limit allowed characters and length
    if not all(c.isalnum() or c in ['.', '-', '_'] for c in username) or len(username) > 64:
        return jsonify({"error": "Invalid username format"}), 400

    if not all(c.isalnum() or c in ['.', '-', '_'] for c in dc) or len(dc) > 64:
        return jsonify({"error": "Invalid dc format"}), 400

    # Construct the search filter using parameterized values.  This prevents LDAP injection.
    search_filter = f"(&(objectClass=person)(uid={username})(dc={dc}))"  # Example filter.  Adjust as needed.
    base_dn = LDAP_BASE_DN # Use the configured base DN

    try:
        # Establish LDAP connection with SSL/TLS
        server = ldap3.Server(LDAP_SERVER, port=LDAP_PORT, use_ssl=True)  #Enforce SSL
        conn = ldap3.Connection(server, user=LDAP_USER, password=LDAP_PASSWORD, auto_bind=True)

        # Perform the LDAP search
        conn.search(base_dn, search_filter, attributes=['*'])  # Specify attributes to retrieve

        if conn.entries:
            # Return the first entry as JSON
            user_data = conn.entries[0].__dict__['attributes']
            conn.unbind()
            return jsonify(user_data), 200
        else:
            conn.unbind()
            return jsonify({"message": "User not found"}), 404

    except ldap3.core.exceptions.LDAPException as e:
        print(f"LDAP Error: {e}")
        return jsonify({"error": f"LDAP error: {e}"}), 500
    except Exception as e:
        print(f"General Error: {e}")
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


@app.route("/register", methods=['POST'])
def register():
    """Registers a new user.  Expects username and password in the request."""
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    # Input validation (same as above, plus password complexity checks)
    if not all(c.isalnum() or c in ['.', '-', '_'] for c in username) or len(username) > 64:
        return jsonify({"error": "Invalid username format"}), 400

    if len(password) < 8:  # Example password complexity
        return jsonify({"error": "Password must be at least 8 characters long"}), 400

    try:
        # Hash the password
        hashed_password, salt = hash_password(password)

        # Convert salt and hash to base64 for storage (e.g., in LDAP)
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        hashed_password_b64 = base64.b64encode(hashed_password).decode('utf-8')

        # Construct the user's DN (Distinguished Name)
        user_dn = f"uid={username},{LDAP_BASE_DN}"

        # Create the user entry in LDAP
        user_attributes = {
            'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
            'uid': [username],
            'cn': [username],  # Common Name
            'sn': [username],  # Surname (can be customized)
            'userPassword': [f'{hashed_password_b64}'], # Store the base64 encoded hash
            'salt': [f'{salt_b64}'] # Store the base64 encoded salt
        }

        server = ldap3.Server(LDAP_SERVER, port=LDAP_PORT, use_ssl=True)
        conn = ldap3.Connection(server, user=LDAP_USER, password=LDAP_PASSWORD, auto_bind=True)

        conn.add(user_dn, attributes=user_attributes)

        if conn.result['result'] == 0:  # Check for success
            conn.unbind()
            return jsonify({"message": "User registered successfully"}), 201
        else:
            conn.unbind()
            return jsonify({"error": f"Failed to register user: {conn.result}"}), 500

    except ldap3.core.exceptions.LDAPException as e:
        print(f"LDAP Error: {e}")
        return jsonify({"error": f"LDAP error: {e}"}), 500
    except Exception as e:
        print(f"General Error: {e}")
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


@app.route("/login", methods=['POST'])
def login():
    """Authenticates a user.  Expects username and password in the request."""
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    try:
        # Search for the user in LDAP to retrieve the stored hash and salt
        search_filter = f"(&(objectClass=person)(uid={username}))"
        base_dn = LDAP_BASE_DN

        server = ldap3.Server(LDAP_SERVER, port=LDAP_PORT, use_ssl=True)
        conn = ldap3.Connection(server, user=LDAP_USER, password=LDAP_PASSWORD, auto_bind=True)

        conn.search(base_dn, search_filter, attributes=['userPassword', 'salt'])

        if not conn.entries:
            conn.unbind()
            return jsonify({"error": "Invalid username or password"}), 401

        user_entry = conn.entries[0]
        hashed_password_b64 = user_entry.userPassword.value  # Get the base64 encoded hash
        salt_b64 = user_entry.salt.value # Get the base64 encoded salt

        # Decode the hash and salt from base64
        hashed_password = base64.b64decode(hashed_password_b64)
        salt = base64.b64decode(salt_b64)

        # Verify the password
        if verify_password(password, hashed_password, salt):
            conn.unbind()
            # In a real application, you would create a session here
            return jsonify({"message": "Login successful"}), 200
        else:
            conn.unbind()
            return jsonify({"error": "Invalid username or password"}), 401

    except ldap3.core.exceptions.LDAPException as e:
        print(f"LDAP Error: {e}")
        return jsonify({"error": f"LDAP error: {e}"}), 500
    except Exception as e:
        print(f"General Error: {e}")
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


if __name__ == '__main__':
    app.run(debug=True)

