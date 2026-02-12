import sys
import shlex
import logging
import re  # For more robust validation

logging.basicConfig(level=logging.INFO)  # Configure logging

MAX_STRING_LENGTH = 256  # Example length limit

def secure_string_processing(user_input, intended_use="shell"):
    """
    Processes a user-provided string, trimming whitespace and newlines,
    and sanitizing it based on the intended use.

    Args:
        user_input: The string to process.
        intended_use:  A string indicating how the processed string will be used.
                       Valid values: "shell", "filename", "database", "email", "generic".
                       Defaults to "shell".

    Returns:
        The processed string, or None if an error occurred.
    """

    if not isinstance(user_input, str):
        logging.error("Input must be a string.")
        return None

    if len(user_input) > MAX_STRING_LENGTH:
        logging.error("Input string too long.")
        return None

    # Trim trailing whitespace and newlines
    processed_string = user_input.rstrip().rstrip('\n')

    if intended_use == "shell":
        # Sanitize for shell command usage
        processed_string = shlex.quote(processed_string)
    elif intended_use == "filename":
        # Sanitize for filename usage (restrict to alphanumeric and underscores)
        processed_string = re.sub(r'[^a-zA-Z0-9_.-]', '', processed_string)  # Allow dots and hyphens
        if processed_string != user_input.rstrip().rstrip('\n'):
            logging.warning(f"Filename sanitization removed characters from input: {user_input}")
    elif intended_use == "database":
        #  Ideally, use parameterized queries instead of string manipulation.
        #  This is a placeholder for that concept.  NEVER directly embed user input
        #  into SQL queries without proper parameterization.
        logging.warning("Database sanitization is a placeholder.  Use parameterized queries!")
        # In a real application, you would *not* do this.  This is just to
        # demonstrate the need for context-specific handling.
        processed_string = processed_string.replace("'", "''") # Example escaping, but INSUFFICIENT
    elif intended_use == "email":
        # Basic email validation (more robust validation is recommended)
        if not re.match(r"[^@]+@[^@]+\.[^@]+", processed_string):
            logging.error("Invalid email format.")
            return None
    elif intended_use == "generic":
        # For generic use, consider escaping HTML entities or other context-specific escaping.
        # This is a placeholder; implement appropriate escaping based on the context.
        logging.info("Generic sanitization: No specific sanitization applied.  Ensure appropriate escaping elsewhere.")
        pass # No specific sanitization for generic use.
    else:
        logging.error(f"Invalid intended_use: {intended_use}")
        return None

    return processed_string


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <string_argument>")
        sys.exit(1)

    user_argument = sys.argv[1]

    # Example usage with different intended uses
    shell_result = secure_string_processing(user_argument, intended_use="shell")
    filename_result = secure_string_processing(user_argument, intended_use="filename")
    database_result = secure_string_processing(user_argument, intended_use="database")
    email_result = secure_string_processing(user_argument, intended_use="email")
    generic_result = secure_string_processing(user_argument, intended_use="generic")

    if shell_result:
        print(f"Shell-processed string: {shell_result}")
    else:
        print("Shell string processing failed.")

    if filename_result:
        print(f"Filename-processed string: {filename_result}")
    else:
        print("Filename string processing failed.")

    if database_result:
        print(f"Database-processed string: {database_result}")
    else:
        print("Database string processing failed.")

    if email_result:
        print(f"Email-processed string: {email_result}")
    else:
        print("Email string processing failed.")

    if generic_result:
        print(f"Generic-processed string: {generic_result}")
    else:
        print("Generic string processing failed.")

