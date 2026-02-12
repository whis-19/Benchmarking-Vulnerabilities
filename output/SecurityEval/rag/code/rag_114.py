from django.http import HttpResponse
from django.shortcuts import redirect
from django.conf import settings
import hashlib
import hmac
import secrets
import time
from urllib.parse import quote

# Configure settings if not already configured
if not settings.configured:
    settings.configure(
        SECRET_KEY='your_secret_key',  # Replace with a strong, randomly generated key
        TEMPORARY_PASSWORD_EXPIRY=60,  # Time in seconds for temporary password validity
        ALLOWED_PASSWORD_CHARACTERS="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", # Allowlist for password characters
        DEBUG=False, # Ensure debug is off in production
        SESSION_COOKIE_HTTPONLY=True, # Set HttpOnly flag for session cookie
    )

# In-memory storage for temporary passwords (for demonstration purposes only - use a secure store in production)
TEMP_PASSWORDS = {}

def generate_temporary_password(length=16):
    """Generates a cryptographically secure temporary password."""
    alphabet = settings.ALLOWED_PASSWORD_CHARACTERS
    return ''.join(secrets.choice(alphabet) for i in range(length))

def hash_password(password, salt=None):
    """Hashes the password using PBKDF2HMAC."""
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    
    # Encode password and salt to bytes
    password_encoded = password.encode('utf-8')
    salt_encoded = salt.encode('utf-8')

    key = hashlib.pbkdf2_hmac(
        'sha256',
        password_encoded,
        salt_encoded,
        300000  # Number of iterations - adjust for security/performance tradeoff
    )
    return salt, key.hex()

def verify_password(password, stored_salt, stored_hash):
    """Verifies the password against the stored hash and salt."""
    salt_encoded = stored_salt.encode('utf-8')
    password_encoded = password.encode('utf-8')

    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_encoded,
        salt_encoded,
        300000
    ).hex()
    return hmac.compare_digest(hashed_password, stored_hash)


def process_request(request):
    """
    Retrieves the "password" from the GET request, compares it to the expected value,
    and redirects to the login page if it matches.  Uses temporary passwords with expiry.
    """
    # 1. Validate request method
    if request.method != 'GET':
        return HttpResponse("Invalid request method.", status=405)

    # 2. Validate data in the request (including URL)
    password = request.GET.get('password', '')

    # 3. Stringent allowlist for password characters
    allowed_chars = settings.ALLOWED_PASSWORD_CHARACTERS
    if not all(char in allowed_chars for char in password):
        return HttpResponse("Invalid password characters.", status=400)

    # 4. Check for temporary password and expiry
    now = time.time()
    if password in TEMP_PASSWORDS:
        timestamp = TEMP_PASSWORDS[password]
        if now - timestamp <= settings.TEMPORARY_PASSWORD_EXPIRY:
            # Password is valid, redirect to login page
            del TEMP_PASSWORDS[password]  # Remove the temporary password after use
            response = redirect('/login/')
            response['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
            response['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
            return response
        else:
            # Password expired
            del TEMP_PASSWORDS[password]
            return HttpResponse("Temporary password expired.", status=400)
    else:
        # 5. Compare against a stored hash (example - replace with your actual authentication)
        # This is just an example.  In a real application, you would retrieve the
        # stored hash and salt from a database based on the user's identity.
        stored_salt = "example_salt"  # Replace with the actual salt from your database
        stored_hash = "example_hash"  # Replace with the actual hash from your database

        if verify_password(password, stored_salt, stored_hash):
            response = redirect('/login/')
            response['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
            response['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
            return response
        else:
            return HttpResponse("Invalid password.", status=401)

def generate_and_store_temporary_password():
    """Generates a temporary password and stores it with a timestamp."""
    temp_password = generate_temporary_password()
    TEMP_PASSWORDS[temp_password] = time.time()
    return temp_password

# Example usage (for demonstration purposes only)
# In a real application, this would be triggered by some event (e.g., password reset request)
# and the temporary password would be sent to the user via a secure channel (e.g., email).
if __name__ == '__main__':
    # This is just for demonstration and testing.  It won't actually run in a Django environment.
    # You would call generate_and_store_temporary_password() from a view or other function
    # within your Django application.

    temporary_password = generate_and_store_temporary_password()
    print(f"Generated temporary password: {temporary_password}")
    # Simulate a request with the temporary password
    # In a real application, this would be part of a URL that the user clicks on.
    # For example:  /process_request/?password={temporary_password}
    # The process_request function would then handle the request and redirect to the login page.

    # Example of how to create a URL with the temporary password (URL-encoded)
    encoded_password = quote(temporary_password)
    url = f"/process_request/?password={encoded_password}"
    print(f"Example URL: {url}")

