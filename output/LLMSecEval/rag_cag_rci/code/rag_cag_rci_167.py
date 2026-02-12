import re

def is_valid_username(username):
    """
    Validates the username against an allowlist of characters.
    """
    pattern = r"^[a-zA-Z0-9_-]+$"  # Allow alphanumeric, underscore, and hyphen
    return bool(re.match(pattern, username))

# ... inside get_user_info:
    if not is_valid_username(username):
        print("Error: Invalid username.  Must be alphanumeric, underscore, or hyphen.")
        return None

