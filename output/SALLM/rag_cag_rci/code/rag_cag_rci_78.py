import re

        def is_valid_username(username):
            pattern = r"^[a-zA-Z0-9_.-]+$"  # Allows alphanumeric, underscore, hyphen, and period
            return bool(re.match(pattern, username))

        if not is_valid_username(username):
            return "Invalid username format", 400

