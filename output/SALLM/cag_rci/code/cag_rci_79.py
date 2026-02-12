import re

def sanitize_command_input(input_string):
    """
    Sanitizes command input by removing potentially dangerous characters.
    This is a VERY BASIC example and needs to be improved significantly.
    """
    # This is a very basic example and should be improved.
    # It only allows alphanumeric characters, underscores, hyphens, and dots.
    sanitized_string = re.sub(r"[^a-zA-Z0-9_\-\.]", "", input_string)
    return sanitized_string

