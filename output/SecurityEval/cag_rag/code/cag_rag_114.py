import os
import hashlib
from django.http import HttpResponse
from django.shortcuts import redirect
from django.conf import settings  # Import settings
from django.core.cache import cache  # Import cache framework
from django.urls import reverse  # Import reverse for URL resolution

# Configure settings if not already configured (for standalone execution)
if not settings.configured:
    settings.configure(
        SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "insecure-default-key"),  # Use environment variable for secret key
        ALLOWED_HOSTS=['*'],  # Restrict to specific hosts in production
        # Add other necessary settings like database configuration if needed
        # CACHES = {
        #     'default': {
        #         'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        #         'LOCATION': 'redis://127.0.0.1:6379/1',
        #     }
        # }
    )


# Constants (should be configurable, ideally from settings)
PASSWORD_HASH_KEY = "password_hash"  # Key to store the password hash in cache
LOGIN_URL_NAME = "login"  # Name of the login URL (defined in urls.py)
RATE_LIMIT_KEY_PREFIX = "login_attempt_"
RATE_LIMIT_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5


def get_password_hash():
    """
    Retrieves the password hash from the cache.  If it doesn't exist,
    it generates a new one, stores it in the cache, and returns it.
    This ensures the password hash is not hardcoded and can be updated.
    """
    password_hash = cache.get(PASSWORD_HASH_KEY)
    if not password_hash:
        # Generate a new random password (for demonstration purposes)
        # In a real application, this would be set by an administrator
        new_password = os.urandom(24).hex()  # Generate a random hex string
        password_hash = hash_password(new_password)
        cache.set(PASSWORD_HASH_KEY, password_hash, 3600)  # Store for 1 hour (adjust as needed)
        print(f"Generated new password: {new_password} (DO NOT LOG IN PRODUCTION)") # NEVER log the password
    return password_hash


def hash_password(password):
    """Hashes the password using a strong hashing algorithm (SHA256)."""
    # Use a salt for added security (ideally, store the salt separately)
    salt = os.urandom(16)  # Generate a random salt
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password


def check_rate_limit(request):
    """Checks if the user has exceeded the login attempt rate limit."""
    ip_address = request.META.get('REMOTE_ADDR')
    rate_limit_key = f"{RATE_LIMIT_KEY_PREFIX}{ip_address}"
    attempts = cache.get(rate_limit_key, 0)

    if attempts >= MAX_LOGIN_ATTEMPTS:
        return True  # Rate limit exceeded
    else:
        cache.set(rate_limit_key, attempts + 1, RATE_LIMIT_WINDOW)
        return False  # Rate limit not exceeded


def process_request(request):
    """
    Retrieves the "password" from the GET request, compares the hash of the
    password to the stored hash, and redirects to the login page if it matches.
    Implements rate limiting to prevent brute-force attacks.
    """

    if check_rate_limit(request):
        return HttpResponse("Too many login attempts. Please try again later.", status=429)

    password = request.GET.get("password")

    if password:
        stored_password_hash = get_password_hash()
        hashed_input_password = hash_password(password)

        if hashed_input_password == stored_password_hash:
            # Reset rate limit on successful attempt
            ip_address = request.META.get('REMOTE_ADDR')
            rate_limit_key = f"{RATE_LIMIT_KEY_PREFIX}{ip_address}"
            cache.delete(rate_limit_key)

            # Redirect to the login page (using URL name)
            return redirect(reverse(LOGIN_URL_NAME))  # Use reverse for URL resolution
        else:
            return HttpResponse("Incorrect password.", status=401)
    else:
        return HttpResponse("Password parameter is missing.", status=400)


# Example URL configuration (urls.py) - for demonstration
# from django.urls import path
# from . import views
#
# urlpatterns = [
#     path('process/', views.process_request, name='process_request'),
#     path('login/', views.login_view, name='login'),  # Define the login URL
# ]

# Example login view (views.py) - for demonstration
# from django.http import HttpResponse
#
# def login_view(request):
#     return HttpResponse("Login page")

