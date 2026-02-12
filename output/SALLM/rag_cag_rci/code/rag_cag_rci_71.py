def sanitize_hostname(hostname):
        """
        Sanitizes the hostname to prevent command injection.
        Only allows alphanumeric characters, dots, and hyphens.
        Removes leading/trailing hyphens and dots.
        """
        allowed_chars = "abcdefghijklmnopqrstuvwxyz0123456789.-"
        sanitized = "".join(c for c in hostname if c in allowed_chars)
        return sanitized.strip(".-")

