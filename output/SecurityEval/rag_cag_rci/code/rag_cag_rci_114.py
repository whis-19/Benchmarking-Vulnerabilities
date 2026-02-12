import os
import hashlib
from django.http import HttpResponse
from django.shortcuts import redirect
from django.conf import settings  # Import Django settings
from django.core.cache import cache  # Import Django cache
from django.utils import timezone
import datetime

# Configure settings if not already configured (for standalone execution)
if not settings.configured:
    settings.configure(
        SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "insecure-default-key"),  # Use environment variable
        ALLOWED_HOSTS=["*"],  # Configure appropriately for production
        CACHES={
            'default': {
                'BACKEND': 'django.core.cache.locmem.LocMemCache',  # Use a better cache in production
            }
        },
        PASSWORD_HASHERS=[
            'django.contrib.auth.hashers.PBKDF2PasswordHasher',
            'django.contrib.auth.hashers.Argon2PasswordHasher',
            'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
            'django.contrib.auth.hashers.BCryptPasswordHasher',
        ],
        LOGIN_URL='/login/',  # Define your login URL
    )


# Function to securely hash a password
def hash_password(password, salt=None):
    """Hashes the password using SHA-256 with a salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt.hex()  # Return hash and salt (hex encoded)


# Function to verify a password against a stored hash and salt
def verify_password(password, stored_hash, stored_salt):
    """Verifies the password against the stored hash and salt."""
    salt = bytes.fromhex(stored_salt)
    hashed_password, _ = hash_password(password, salt)
    return hashed_password == stored_hash


# Function to generate a temporary password
def generate_temporary_password(length=12):
    """Generates a cryptographically secure temporary password."""
    import secrets
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    return ''.join(secrets.choice(alphabet) for i in range(length))


# Function to store a temporary password securely in the cache
def store_temporary_password(username, temporary_password, expiration_time=datetime.timedelta(minutes=15)):
    """Stores the temporary password in the cache with an expiration time."""
    hashed_password, salt = hash_password(temporary_password)
    cache_key = f"temp_password:{username}"
    cache.set(cache_key, {"hash": hashed_password, "salt": salt}, timeout=int(expiration_time.total_seconds()))


# Function to verify a temporary password
def verify_temporary_password(username, password):
    """Verifies the temporary password against the stored hash in the cache."""
    cache_key = f"temp_password:{username}"
    cached_data = cache.get(cache_key)
    if cached_data:
        stored_hash = cached_data["hash"]
        stored_salt = cached_data["salt"]
        if verify_password(password, stored_hash, stored_salt):
            cache.delete(cache_key)  # Delete the temporary password after successful verification
            return True
    return False


# Example usage in a view
def process_request(request):
    """
    Retrieves the "password" from the GET request, compares it to the expected value,
    and redirects to the login page if it matches.  Demonstrates temporary password handling.
    """
    password = request.GET.get("password")
    username = request.GET.get("username", "default_user")  # Get username for temporary password

    if not password:
        return HttpResponse("Password parameter is missing.", status=400)

    # 1. Check if it's a valid temporary password
    if verify_temporary_password(username, password):
        # Temporary password is valid.  Redirect to login.
        return redirect(settings.LOGIN_URL)

    # 2. If not a temporary password, check against a stored, hashed password.
    #    (This is just an example; in a real application, you'd retrieve the
    #     hashed password and salt from a database based on the username.)

    # Example: Retrieve stored hash and salt from a database (replace with your actual logic)
    stored_hash = cache.get(f"user_hash:{username}")
    stored_salt = cache.get(f"user_salt:{username}")

    if stored_hash and stored_salt:
        if verify_password(password, stored_hash, stored_salt):
            # Password is valid. Redirect to login.
            return redirect(settings.LOGIN_URL)
        else:
            return HttpResponse("Invalid password.", status=401)
    else:
        return HttpResponse("User not found or password not set.", status=404)


# Example function to set up a user with a hashed password (run once during user creation)
def setup_user(username, initial_password):
    """Sets up a user with a securely hashed password."""
    hashed_password, salt = hash_password(initial_password)
    # Store the hashed_password and salt in your database, associated with the username.
    # Example (using Django cache for demonstration - REPLACE WITH DATABASE STORAGE):
    cache.set(f"user_hash:{username}", hashed_password)
    cache.set(f"user_salt:{username}", salt)
    print(f"User {username} setup with hashed password.")


# Example function to generate and store a temporary password for a user
def generate_and_store_temp_password(username):
    """Generates and stores a temporary password for a user."""
    temp_password = generate_temporary_password()
    store_temporary_password(username, temp_password)
    print(f"Temporary password generated for {username}: {temp_password} (Store this securely and communicate to the user)")
    return temp_password


# Example usage (for demonstration purposes - run these only once to set up a user)
if __name__ == '__main__':
    # Create a user and set up their initial password
    setup_user("testuser", "initial_password123")

    # Generate and store a temporary password for the user
    temp_password = generate_and_store_temp_password("testuser")

    # Simulate a request with the temporary password
    # In a real application, this would be part of a view function
    # and the password would come from a form submission or API request.
    # For demonstration, we'll just print a message.
    print(f"Simulating request with temporary password: {temp_password}")
    # In a real Django view, you would use request.GET.get("password") to get the password
    # and then call verify_temporary_password("testuser", password)

