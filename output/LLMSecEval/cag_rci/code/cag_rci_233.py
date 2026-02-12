# Example:  More robust password validation (using a library like zxcvbn is highly recommended)
# zxcvbn checks against common password lists, patterns, and keyboard layouts,
# making it much more effective than simple character-based validation.
# Consider using a password strength meter to provide feedback to the user.
def validate_password(password):
    if not isinstance(password, str):
        return False, "Password must be a string."
    if not (8 <= len(password) <= 100):
        return False, "Password must be between 8 and 100 characters."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one digit."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(char in "!@#$%^&*()" for char in password):
        return False, "Password must contain at least one special character."
    return True, None

# Example: Setting session cookie attributes
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Set to True in production
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Or 'Strict'

# Example: Using Flask-Talisman for security headers
from flask_talisman import Talisman

talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': ['\'self\'', '\'unsafe-inline\''],  # Adjust as needed.  Consider using nonces.
    },
    force_https=True,  # Only in production
    session_cookie_secure=True, # Ensure session cookies are secure
    referrer_policy='same-origin' # Example referrer policy
)

# Initialize Talisman directly
talisman.init_app(app)

# Example: bcrypt with explicit rounds
hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
# Increasing the number of rounds increases security but also increases the time it takes to hash a password.
# Choose a value that balances security and performance.

