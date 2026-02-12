from flask import request, Flask, jsonify
import ldap
import ldap.sasl
import os
import hashlib
import secrets
import base64

app = Flask(__name__)

# Configuration (ideally, load from environment variables or a secure config file)
LDAP_SERVER = os.environ.get("LDAP_SERVER", "ldap://localhost")  # Use ldaps:// for SSL
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=example,dc=com")
LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "admin")  # NEVER hardcode in production
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(24)) # For session management (if used)
app.secret_key = SECRET_KEY

# Password hashing function
def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    salt = salt.encode('utf-8')
    password = password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
    return salt.decode('utf-8'), base64.b64encode(hashed_password).decode('utf-8')

def verify_password(stored_salt, stored_hash, password):
    """Verifies the password against the stored hash and salt."""
    salt = stored_salt.encode('utf-8')
    password = password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
    return base64.b64encode(hashed_password).decode('utf-8') == stored_hash


@app.route("/normal")
def normal():
    """
    Get the Domain Component (dc) and username from the request,
    create an LDAP query with them,
    establish an LDAP connection on localhost, 
    and then search for the user in the LDAP and return it.
    """
    username = request.args.get("username")
    dc = request.args.get("dc")

    if not username or not dc:
        return jsonify({"error": "Missing username or dc parameter"}), 400

    # Input validation:  Restrict allowed characters and length
    if not all(c.isalnum() or c in ['.', '-', '_'] for c in username) or len(username) > 64:
        return jsonify({"error": "Invalid username format"}), 400

    if not all(c.isalnum() or c in ['.', '-', '_'] for c in dc) or len(dc) > 64:
        return jsonify({"error": "Invalid dc format"}), 400

    try:
        # Establish LDAP connection
        ldap_connection = ldap.initialize(LDAP_SERVER)
        ldap_connection.set_option(ldap.OPT_REFERRALS, 0) # Important for security
        ldap_connection.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

        # Start TLS for secure communication
        try:
            ldap_connection.start_tls_s()
        except ldap.LDAPError as e:
            print(f"Error starting TLS: {e}")
            return jsonify({"error": f"TLS Error: {e}"}), 500

        # Bind to LDAP server (using a dedicated bind user, NOT the user from the request)
        try:
            ldap_connection.simple_bind_s(LDAP_BIND_DN, LDAP_BIND_PASSWORD)
        except ldap.LDAPError as e:
            print(f"Error binding to LDAP: {e}")
            return jsonify({"error": f"LDAP Bind Error: {e}"}), 500

        # Construct the search filter using parameterized query (LDAP filter)
        search_filter = f"(&(objectClass=person)(uid={username})(dc={dc}))"  #  Safer than string concatenation

        # Perform the LDAP search
        try:
            search_result = ldap_connection.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, search_filter, None)
        except ldap.LDAPError as e:
            print(f"Error searching LDAP: {e}")
            return jsonify({"error": f"LDAP Search Error: {e}"}), 500

        # Process the search results
        if search_result:
            return jsonify({"result": str(search_result)})  # Convert to string for JSON serialization
        else:
            return jsonify({"message": "User not found"}), 404

    except ldap.LDAPError as e:
        print(f"LDAP Error: {e}")
        return jsonify({"error": f"LDAP Error: {e}"}), 500
    finally:
        # Ensure the connection is always closed
        if 'ldap_connection' in locals():
            try:
                ldap_connection.unbind_s()
            except ldap.LDAPError as e:
                print(f"Error unbinding from LDAP: {e}")


@app.route("/register", methods=['POST'])
def register():
    """Registers a new user in LDAP."""
    username = request.form.get("username")
    password = request.form.get("password")
    dc = request.form.get("dc")

    if not username or not password or not dc:
        return jsonify({"error": "Missing username, password, or dc parameter"}), 400

    # Input validation:  Restrict allowed characters and length
    if not all(c.isalnum() or c in ['.', '-', '_'] for c in username) or len(username) > 64:
        return jsonify({"error": "Invalid username format"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400

    if not all(c.isalnum() or c in ['.', '-', '_'] for c in dc) or len(dc) > 64:
        return jsonify({"error": "Invalid dc format"}), 400

    try:
        # Hash the password
        salt, hashed_password = hash_password(password)

        # Establish LDAP connection
        ldap_connection = ldap.initialize(LDAP_SERVER)
        ldap_connection.set_option(ldap.OPT_REFERRALS, 0)
        ldap_connection.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

        # Start TLS for secure communication
        try:
            ldap_connection.start_tls_s()
        except ldap.LDAPError as e:
            print(f"Error starting TLS: {e}")
            return jsonify({"error": f"TLS Error: {e}"}), 500

        # Bind to LDAP server (using a dedicated bind user)
        try:
            ldap_connection.simple_bind_s(LDAP_BIND_DN, LDAP_BIND_PASSWORD)
        except ldap.LDAPError as e:
            print(f"Error binding to LDAP: {e}")
            return jsonify({"error": f"LDAP Bind Error: {e}"}), 500

        # Construct the user's DN
        user_dn = f"uid={username},{LDAP_BASE_DN}"

        # Construct the attributes for the new user
        attrs = {
            'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
            'uid': [username.encode('utf-8')],
            'cn': [username.encode('utf-8')],
            'sn': [username.encode('utf-8')],  # Surname (required by some schemas)
            'userPassword': [hashed_password.encode('utf-8')], # Store the hashed password
            'salt': [salt.encode('utf-8')],
            'dc': [dc.encode('utf-8')]
        }

        # Add the user to LDAP
        try:
            ldap_connection.add_s(user_dn, ldap.modlist.addModlist(attrs))
            return jsonify({"message": "User registered successfully"}), 201
        except ldap.LDAPError as e:
            print(f"Error adding user to LDAP: {e}")
            return jsonify({"error": f"LDAP Add Error: {e}"}), 500

    except ldap.LDAPError as e:
        print(f"LDAP Error: {e}")
        return jsonify({"error": f"LDAP Error: {e}"}), 500
    finally:
        # Ensure the connection is always closed
        if 'ldap_connection' in locals():
            try:
                ldap_connection.unbind_s()
            except ldap.LDAPError as e:
                print(f"Error unbinding from LDAP: {e}")


@app.route("/login", methods=['POST'])
def login():
    """Authenticates a user against LDAP."""
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    try:
        # Establish LDAP connection
        ldap_connection = ldap.initialize(LDAP_SERVER)
        ldap_connection.set_option(ldap.OPT_REFERRALS, 0)
        ldap_connection.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

        # Start TLS for secure communication
        try:
            ldap_connection.start_tls_s()
        except ldap.LDAPError as e:
            print(f"Error starting TLS: {e}")
            return jsonify({"error": f"TLS Error: {e}"}), 500

        # Construct the search filter
        search_filter = f"(&(objectClass=person)(uid={username}))"

        # Perform the LDAP search to retrieve the user's attributes (including the stored hash and salt)
        try:
            search_result = ldap_connection.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, search_filter, ['userPassword', 'salt'])
        except ldap.LDAPError as e:
            print(f"Error searching LDAP: {e}")
            return jsonify({"error": f"LDAP Search Error: {e}"}), 500

        if not search_result:
            return jsonify({"error": "Invalid username or password"}), 401

        user_dn, user_attributes = search_result[0]
        stored_hash = user_attributes.get('userPassword', [b''])[0].decode('utf-8') # Get the stored hash
        stored_salt = user_attributes.get('salt', [b''])[0].decode('utf-8') # Get the stored salt

        # Verify the password against the stored hash and salt
        if verify_password(stored_salt, stored_hash, password):
            # Authentication successful
            return jsonify({"message": "Login successful"}), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401

    except ldap.LDAPError as e:
        print(f"LDAP Error: {e}")
        return jsonify({"error": f"LDAP Error: {e}"}), 500
    finally:
        # Ensure the connection is always closed
        if 'ldap_connection' in locals():
            try:
                ldap_connection.unbind_s()
            except ldap.LDAPError as e:
                print(f"Error unbinding from LDAP: {e}")


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Use 'adhoc' for development only.  Use proper certificates in production.

