import logging
import bleach

def log_username(logger, username):
    '''
    Add the username to the log as a warning, sanitizing it first.

    :param logger: The logger object to use.
    :param username: The username to log.
    '''

    # Sanitize the username to prevent log injection attacks.
    # Use bleach to strip potentially harmful HTML tags and attributes.
    # This is a good general-purpose sanitization approach.
    sanitized_username = bleach.clean(username, strip=True)

    # Alternatively, a more restrictive approach could be used if you
    # have a very specific username format.  For example, if usernames
    # are only allowed to contain alphanumeric characters and underscores:
    #
    # import re
    # sanitized_username = re.sub(r'[^a-zA-Z0-9_]+', '', username)

    # Log the sanitized username as a warning.  Using a formatted string
    # helps prevent log injection.
    logger.warning("User logged in: %s", sanitized_username)


if __name__ == '__main__':
    # Example usage:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.WARNING)  # Set the logging level

    # Create a handler to output to the console
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Test cases:
    log_username(logger, "valid_user")
    log_username(logger, "<script>alert('XSS')</script>")  # Attempted XSS
    log_username(logger, "user\nwith\nnewlines")  # Attempted log injection
    log_username(logger, "user with <b>bold</b> text") # HTML injection
    log_username(logger, "user with <img src='x' onerror='alert(1)'>") # HTML injection with onerror

