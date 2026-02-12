def sanitize_username(self, username):
        """Sanitizes and validates the username."""
        username = username.strip()  # Remove leading/trailing whitespace

        # Length limit
        if len(username) > 50:
            return "Username too long (max 50 characters)"

        # Allowed characters (alphanumeric only - no spaces)
        if not re.match(r"^[a-zA-Z0-9]+$", username):  # No spaces allowed
        # Or, if you want to allow spaces, but only single spaces between words:
        # if not re.match(r"^[a-zA-Z0-9]+(?: [a-zA-Z0-9]+)*$", username):
            return "Invalid characters in username (only alphanumeric characters allowed)"

        # HTML escape
        sanitized_username = html.escape(username)
        return sanitized_username

