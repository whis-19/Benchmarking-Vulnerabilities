def sanitize_input(input_string):
        """
        Sanitizes the input string to prevent XSS and other injection attacks.
        Using Bleach for robust sanitization.
        """
        if not isinstance(input_string, str):
            logging.warning("Non-string input received for sanitization.")
            return ""  # Or raise an exception: raise TypeError("Input must be a string")

        # Use Bleach to sanitize the input
        allowed_tags = ['a', 'b', 'i', 'strong', 'em', 'p', 'br']  # Example: Allow basic formatting tags
        allowed_attributes = {'a': ['href', 'title']}  # Example: Allow href and title attributes on <a> tags
        sanitized_string = bleach.clean(input_string, tags=allowed_tags, attributes=allowed_attributes, strip=True)
        return sanitized_string

