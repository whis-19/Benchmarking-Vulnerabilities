from flask import request, Flask, jsonify
import ldap
import ldap.sasl
import os  # For environment variables
import secrets  # For generating secure tokens

app = Flask(__name__)

# Configuration (ideally from environment variables)
LDAP_SERVER = os.environ.get("LDAP_SERVER", "ldap://localhost")  # Use ldaps:// for secure connection
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=example,dc=com")  # Base DN for your directory
LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")  # DN for bind user
LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "admin")  # Password for bind user
DEBUG_MODE = os.environ.get("DEBUG_MODE", "False").lower() == "true" # Enable debug mode

# Secret key for session management (if needed)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(24))  # Generate a strong secret key if not provided

def authenticate_ldap(username, password):
    """
    Authenticates a user against the LDAP server.

    Args:
        username (str): The username to authenticate.
        password (str): The password to authenticate.

    Returns:
        bool: True if authentication is successful, False otherwise.
    """
    try:
        ldap_connection = ldap.initialize(LDAP_SERVER)
        ldap_connection.set_option(ldap.OPT_REFERRALS, 0)  # Important for security and performance
        ldap_connection.simple_bind_s(f"uid={username},{LDAP_BASE_DN}", password)  # Bind with user's credentials
        return True
    except ldap.INVALID_CREDENTIALS:
        return False
    except ldap.LDAPError as e:
        print(f"LDAP Authentication Error: {e}")  # Log the error
        return False
    finally:
        try:
            ldap_connection.unbind_s()  # Close the connection
        except:
            pass # Connection might not be established

@app.route("/normal", methods=['POST'])  # Use POST for sensitive data
def normal():
    """
    Retrieves user information from LDAP based on username.
    Requires authentication.
    """
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if not authenticate_ldap(username, password):
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        ldap_connection = ldap.initialize(LDAP_SERVER)
        ldap_connection.set_option(ldap.OPT_REFERRALS, 0)
        ldap_connection.simple_bind_s(LDAP_BIND_DN, LDAP_BIND_PASSWORD)  # Bind with admin credentials

        search_filter = f"uid={username}"  # Search by username (uid)
        search_result = ldap_connection.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, search_filter)

        if search_result:
            dn, attributes = search_result[0]  # Get the first result
            # Sanitize the attributes before returning them.  Remove binary data.
            sanitized_attributes = {}
            for key, value in attributes.items():
                if isinstance(value, list):
                    sanitized_attributes[key] = [v.decode('utf-8', 'ignore') if isinstance(v, bytes) else str(v) for v in value]
                elif isinstance(value, bytes):
                    sanitized_attributes[key] = value.decode('utf-8', 'ignore')
                else:
                    sanitized_attributes[key] = str(value)

            return jsonify({"dn": dn, "attributes": sanitized_attributes})
        else:
            return jsonify({"message": "User not found"}), 404

    except ldap.LDAPError as e:
        print(f"LDAP Search Error: {e}")  # Log the error
        return jsonify({"error": f"LDAP Error: {e}"}), 500
    finally:
        try:
            ldap_connection.unbind_s()  # Close the connection
        except:
            pass # Connection might not be established

if __name__ == "__main__":
    app.run(debug=DEBUG_MODE)

