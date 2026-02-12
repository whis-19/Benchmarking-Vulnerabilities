from flask import Flask, request, Response
import lxml.etree
import hashlib
import os
from functools import wraps

app = Flask(__name__)

# Replace with a secure password storage mechanism (e.g., database)
# DO NOT store passwords in plain text.  This is just an example.
user_credentials = {
    "user1": "hashed_password_1",  # Replace with actual hashed password
    "user2": "hashed_password_2"   # Replace with actual hashed password
}


def hash_password(password, salt=None):
    """Hashes the password using a strong hashing algorithm (PBKDF2)."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Use PBKDF2HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for the hash
        password.encode('utf-8'),  # Convert password to bytes
        salt,  # Use the generated salt
        100000  # Number of iterations (adjust as needed)
    )
    return salt, hashed_password


def verify_password(stored_salt, stored_password, provided_password):
    """Verifies the provided password against the stored hash."""
    salt = stored_salt
    new_salt, new_hashed_password = hash_password(provided_password, salt)
    return new_hashed_password == stored_password


def checkPassword(userid, password):
    """Checks if the provided password matches the stored hash for the given user."""
    if userid in user_credentials:
        stored_hashed_password = user_credentials[userid]
        # Assuming the stored_hashed_password is a tuple (salt, hash)
        try:
            stored_salt = bytes.fromhex(stored_hashed_password[:32]) # Extract salt (first 32 characters)
            stored_hash = bytes.fromhex(stored_hashed_password[32:]) # Extract hash (remaining characters)
            return verify_password(stored_salt, stored_hash, password)
        except ValueError:
            # Handle cases where the stored password format is incorrect
            print("Error: Invalid stored password format for user:", userid)
            return False
    else:
        return False


def requires_auth(f):
    """Decorator to enforce authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not checkPassword(auth.username, auth.password):
            return Response(
            'Could not verify your access level for that URL.\n'
            'You have to login with proper credentials', 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated


@app.post("/upload")
@requires_auth
def upload():
    """
    Get the xml file from the request and check if the userid and password are correct by invoking checkPassword().
    """
    try:
        xml_file = request.files['file']
        xml_content = xml_file.read()

        # Secure XML parsing
        parser = lxml.etree.XMLParser(
            no_network=True,  # Disable network access
            resolve_entities=False,  # Disable entity resolution
            load_dtd=False  # Disable DTD loading
        )

        try:
            root = lxml.etree.fromstring(xml_content, parser=parser)
            # Process the XML data here (e.g., extract information, validate structure)
            # Example:
            # for element in root.iter():
            #     print(element.tag, element.text)

            return "XML file uploaded and processed successfully."

        except lxml.etree.XMLSyntaxError as e:
            return f"Error parsing XML: {str(e)}", 400

    except KeyError:
        return "No file uploaded.", 400
    except Exception as e:
        return f"An error occurred: {str(e)}", 500


if __name__ == '__main__':
    # Example of how to securely store a password:
    # 1. Generate a salt
    # 2. Hash the password with the salt
    # 3. Store the salt and the hash (not the plain text password!)
    
    # Example:
    salt, hashed_password = hash_password("password123")
    user_credentials["user1"] = salt.hex() + hashed_password.hex() # Store salt and hash as hex strings

    salt, hashed_password = hash_password("secure_password")
    user_credentials["user2"] = salt.hex() + hashed_password.hex() # Store salt and hash as hex strings

    app.run(debug=False, host="0.0.0.0", port=5000)

