import hashlib
import os

# Store admin credentials securely (e.g., in environment variables or a database)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")  # Store the HASHED password, not the plain text

HAS_ADMIN_ACCESS = False  # Global flag, initially set to False

def verify_password(password, stored_hash):
    """Verify a stored password against one provided by user"""
    # Separate the salt from the hash
    salt = stored_hash[:64]
    stored_hash = stored_hash[64:]

    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = pwdhash.hex()
    return pwdhash == stored_hash


def admin_access(request):
    """
    Read the username and password from the request, validate them for admin access,
    and set the HAS_ADMIN_ACCESS flag if successful.

    Args:
        request:  A dictionary-like object representing the request.  This should contain
                  'username' and 'password' keys.  The exact structure depends on the
                  framework you're using (e.g., Flask, Django).

    Returns:
        bool: True if admin access is granted, False otherwise.
    """
    global HAS_ADMIN_ACCESS  # Access the global variable

    username = request.get("username")
    password = request.get("password")

    if not username or not password:
        print("Username or password missing from request.")  # Log this for debugging
        HAS_ADMIN_ACCESS = False
        return False

    if username == ADMIN_USERNAME and ADMIN_PASSWORD_HASH:
        if verify_password(password, ADMIN_PASSWORD_HASH):
            HAS_ADMIN_ACCESS = True
            print("Admin access granted.") # Log this for auditing
            return True
        else:
            print("Incorrect password.") # Log this for auditing
            HAS_ADMIN_ACCESS = False
            return False
    else:
        print("Incorrect username or password.") # Log this for auditing
        HAS_ADMIN_ACCESS = False
        return False


def generate_secure_password_hash(password):
    """Generate a secure password hash using PBKDF2."""
    salt = os.urandom(32).hex()  # Generate a random salt
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)  # Use PBKDF2 with SHA512 and a high iteration count
    pwdhash = pwdhash.hex()
    return salt + pwdhash  # Store salt and hash together


# Example usage (for setting up the admin password initially):
if __name__ == '__main__':
    # NEVER store the password directly in the code!
    # This is just for demonstration purposes.  Use environment variables or a secure configuration file.
    example_admin_password = "my_secret_admin_password"  # Replace with a strong password
    hashed_password = generate_secure_password_hash(example_admin_password)
    print(f"Hashed password: {hashed_password}")

    # Store the hashed_password in your environment variables or database.
    # For example, you might set an environment variable like this:
    # export ADMIN_PASSWORD_HASH="<the hashed password from above>"
    # and ADMIN_USERNAME="admin"

    # Example usage of the admin_access function (simulating a request):
    request_data = {"username": "admin", "password": example_admin_password}  # Replace "admin" with your actual username
    if admin_access(request_data):
        print("Admin access granted (simulated).")
    else:
        print("Admin access denied (simulated).")

    print(f"HAS_ADMIN_ACCESS: {HAS_ADMIN_ACCESS}")

