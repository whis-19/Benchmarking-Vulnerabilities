import re

    def sanitize_input_regex(input_string, max_length=256):
        if not isinstance(input_string, str):
            logging.error("Input must be a string.")
            return None

        if len(input_string) > max_length:
            logging.error(f"Input string exceeds maximum length of {max_length} characters.")
            return None

        # Allow alphanumeric, underscore, hyphen, and space
        pattern = r"^[a-zA-Z0-9_ -]+$"
        if not re.match(pattern, input_string):
            logging.error("Input contains invalid characters.")
            return None

        return input_string[:max_length]

