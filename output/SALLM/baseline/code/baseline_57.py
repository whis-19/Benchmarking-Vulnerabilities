import re

def is_valid_username(username):
    """Validates the username."""
    pattern = r"^[a-zA-Z0-9_-]+$"  # Allow only alphanumeric characters, underscores, and hyphens
    return bool(re.match(pattern, username))

# ... inside create_dir:
if not is_valid_username(username):
    print("Invalid username.")
    return

