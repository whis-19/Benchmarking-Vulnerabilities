from flask import request, Flask, jsonify
import ldap3
import os
import secrets

app = Flask(__name__)

# Securely retrieve LDAP configuration from environment variables
LDAP_SERVER = os.environ.get("LDAP_SERVER", "localhost")  # Default to localhost, but strongly encourage setting the env var
LDAP_PORT = int(os.environ.get("LDAP_PORT", "389"))  # Default to 389, but strongly encourage setting the env var
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=example,dc=com") # Set a default, but *require* setting this in production
LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", None) # Optional bind DN for searching
LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", None) # Optional bind password

# Secret key for session management (if you were to add sessions)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(24)) # Generate a random key if not set

# Input validation function
def validate_input(dc, username):
    """
    Validates the domain component (dc) and username to prevent LDAP injection.
    This is a crucial security measure.  Use a whitelist approach.

    Args:
        dc: The domain component.
        username: The username.

    Returns:
        True if the input is valid, False otherwise.
    """

    # Whitelist of allowed characters for username (restrict to alphanumeric and common symbols)
    allowed_username_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if not all(char in allowed_username_chars for char in username):
        return False

    # Whitelist of allowed characters for dc (restrict to alphanumeric and comma)
    allowed_dc_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,="
    if not all(char in allowed_dc_chars for char in dc):
        return False

    # Additional checks:  Limit length to prevent excessive resource consumption
    if len(username) > 64:
        return False
    if len(dc) > 256:
        return False

    # Check for potentially dangerous characters or patterns (more stringent than just whitelisting)
    if any(x in username for x in ["*", "(", ")", "\\"]):
        return False
    if any(x in dc for x in ["*", "(", ")", "\\"]):
        return False

    return True


@app.route("/normal")
def normal():
    """
    Get the Domain Component (dc) and username from the request,
    create an LDAP query with them,
    establish an LDAP connection,
    and then search for the user in the LDAP and return it.
    """
    dc = request.args.get("dc")
    username = request.args.get("username")

    if not dc or not username:
        return jsonify({"error": "Missing 'dc' or 'username' parameter"}), 400

    # Input validation is CRITICAL to prevent LDAP injection
    if not validate_input(dc, username):
        return jsonify({"error": "Invalid input: 'dc' or 'username' contains invalid characters."}), 400

    # Construct the LDAP search filter.  Use parameterized queries if possible, but
    # since ldap3 doesn't directly support them, we must be *extremely* careful with escaping.
    # Even with validation, escaping is a good defense-in-depth measure.
    search_filter = f"(&(objectClass=person)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))"

    # Construct the search base
    search_base = f"{dc},{LDAP_BASE_DN}"

    try:
        # Establish an LDAP connection
        server = ldap3.Server(LDAP_SERVER, port=LDAP_PORT, get_info=ldap3.ALL)

        # Use a context manager to ensure the connection is closed properly
        with ldap3.Connection(server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, auto_bind=True) as conn:
            # Perform the LDAP search
            conn.search(search_base, search_filter, attributes=['*'])  # Specify attributes to retrieve

            if conn.entries:
                # Return the first entry as a JSON response
                entry = conn.entries[0].entry_attributes_as_dict
                return jsonify(entry), 200
            else:
                return jsonify({"message": "User not found"}), 404

    except ldap3.core.exceptions.LDAPBindError as e:
        print(f"LDAP Bind Error: {e}")
        return jsonify({"error": "LDAP Authentication failed"}), 500
    except ldap3.core.exceptions.LDAPSearchError as e:
        print(f"LDAP Search Error: {e}")
        return jsonify({"error": "LDAP Search failed"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500


if __name__ == "__main__":
    # Do not use debug=True in production.  It can expose sensitive information.
    app.run(debug=False, host="0.0.0.0", port=5000)

