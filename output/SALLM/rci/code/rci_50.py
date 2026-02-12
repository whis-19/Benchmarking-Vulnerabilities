import logging
import bleach
import re
import unicodedata

def log_username(logger, username):
    '''
    Add the username to the log, sanitizing it to prevent log injection and XSS.

    :param logger: The logger object to use.
    :param username: The username to log.
    '''

    if not isinstance(username, str):
        logger.warning(f"Invalid username type: {type(username)}.  Using 'INVALID_USERNAME'.")
        username = "INVALID_USERNAME"

    try:
        # Sanitize the username using bleach with a stricter allowlist.
        allowed_tags = []  # Only allow specific tags if needed, otherwise keep empty
        allowed_attributes = {} # Only allow specific attributes if needed, otherwise keep empty

        sanitized_username = bleach.clean(username, tags=allowed_tags, attributes=allowed_attributes, strip=True)

        # Prevent log injection by removing newline and carriage return characters.
        sanitized_username = re.sub(r"[\r\n]+", "", sanitized_username)

        # Unicode normalization (NFKC is a good choice for security)
        sanitized_username = unicodedata.normalize('NFKC', sanitized_username)


    except (TypeError, ValueError) as e:
        # Handle potential errors during sanitization.  Log the error and use a safe default.
        logger.exception("Error sanitizing username: %s", e) # Use logger.exception to include traceback
        sanitized_username = "SANITIZATION_ERROR"  # Or a more appropriate default
    except Exception as e:
        logger.exception("Unexpected error sanitizing username: %s", e)
        sanitized_username = "UNEXPECTED_SANITIZATION_ERROR"


    # Log the sanitized username.  Using a formatted string prevents log injection.
    logger.debug("User logged in: %s", sanitized_username)  # Consider INFO or DEBUG


if __name__ == '__main__':
    # Example usage:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)  # Set the logging level to DEBUG

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
    log_username(logger, None) # Test with None input
    log_username(logger, 123) # Test with integer input
    log_username(logger, "user with unicode: ☢") # Test with unicode
    log_username(logger, "user with unicode that looks like ascii: K") # Test with unicode that looks like ascii

