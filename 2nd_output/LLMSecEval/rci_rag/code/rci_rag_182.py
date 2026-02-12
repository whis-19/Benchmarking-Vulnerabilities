import re

    def is_valid_username(username):
        pattern = r"^[a-zA-Z][a-zA-Z0-9_]{3,15}$"  # Starts with letter, 4-16 chars, alphanumeric + underscore
        return bool(re.match(pattern, username))

