import re
import secrets
import logging
import string
import urllib.parse
import bcrypt  # Or argon2-cffi

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class RegexError(Exception):
    """Custom exception for regular expression errors."""
    pass


class RegexTimeoutError(Exception):
    """Custom exception for regular expression timeout errors."""
    pass


def search_pattern(pattern, string, timeout=0.1):
    """
    Safely searches for a pattern within a string using regular expressions.

    This function prioritizes security by:
    1.  Using `re.escape` to sanitize the pattern, preventing potential
        regular expression injection attacks.
    2.  Limiting the complexity of the regex search to mitigate potential
        ReDoS (Regular expression Denial of Service) attacks.  This is done
        by setting a timeout.  The timeout value should be adjusted based on
        the expected complexity of the patterns and strings being processed.
    3.  Handling potential `re.error` and `TimeoutError` exceptions gracefully,
        logging errors, and raising custom exceptions.

    :param pattern: The regular expression pattern to search for.
    :param string: The string to search within.
    :param timeout: The maximum time (in seconds) to allow for the regex search.
    :return: True if the pattern is found in the string, False otherwise.
    :raises RegexError: If the regular expression is invalid.
    :raises RegexTimeoutError: If the regular expression search times out.
    """
    try:
        # Sanitize the pattern to prevent regex injection
        escaped_pattern = re.escape(pattern)

        # Compile the regex with a timeout to prevent ReDoS
        compiled_pattern = re.compile(escaped_pattern, timeout=timeout)

        # Search for the pattern
        match = compiled_pattern.search(string)

        return bool(match)  # Return True if a match is found, False otherwise

    except re.error as e:
        logging.error(f"Error in regular expression: {e}")
        raise RegexError(f"Invalid regular expression: {e}") from e
    except TimeoutError:
        logging.warning("Regular expression search timed out.")
        raise RegexTimeoutError("Regular expression search timed out.")


def is_valid_url(target_url):
    """
    Checks if the input URL is a valid URL using urllib.parse.

    This function validates the URL by parsing it and checking for a valid scheme and netloc.
    It's more robust than using a simple regex for URL validation.

    :param target_url: The URL to be checked.
    :return: True if the URL is valid, False otherwise.
    """
    try:
        result = urllib.parse.urlparse(target_url)
        return all([result.scheme, result.netloc])
    except Exception:  # Catch more specific exceptions if possible
        logging.error("Error parsing URL in is_valid_url", exc_info=True)
        return False


def match_url(target_url, allowed_domains=None, allowed_schemes=('http', 'https'), allowed_paths=None):
    """
    Check if the input URL matches the specified criteria.

    :param target_url: The URL to be checked.
    :param allowed_domains: A list of allowed domains (e.g., ['example.com', 'another.com']).  If None, any domain is allowed.
    :param allowed_schemes: A tuple of allowed schemes (e.g., ('http', 'https')).
    :param allowed_paths: A list of allowed paths or a regex pattern for paths. If None, any path is allowed.
    :return: True if the URL is valid and matches the criteria, False otherwise.
    """
    try:
        result = urllib.parse.urlparse(target_url)

        if not result.scheme or not result.netloc:
            return False

        if allowed_schemes and result.scheme not in allowed_schemes:
            return False

        if allowed_domains and result.netloc not in allowed_domains:
            return False

        if allowed_paths:
            if isinstance(allowed_paths, str):  # Regex pattern
                if not re.match(allowed_paths, result.path):
                    return False
            elif isinstance(allowed_paths, list) and result.path not in allowed_paths:  # List of paths
                return False
            else:
                return False # Invalid allowed_paths type

        # Reconstruct the URL and compare to detect normalization issues
        reconstructed_url = urllib.parse.urlunparse(result)
        if target_url != reconstructed_url:
            logging.warning(f"URL normalization detected: Original: {target_url}, Reconstructed: {reconstructed_url}")
            return False

        return True

    except Exception as e:  # Catch more specific exceptions if possible
        logging.error(f"Error parsing URL: {e}", exc_info=True)
        return False


def generate_secure_password(length=16, include_symbols=True, include_digits=True, include_uppercase=True, include_lowercase=True):
    """
    Generates a cryptographically secure random password.

    :param length: The desired length of the password.
    :param include_symbols: Whether to include symbols in the password.
    :param include_digits: Whether to include digits in the password.
    :param include_uppercase: Whether to include uppercase letters in the password.
    :param include_lowercase: Whether to include lowercase letters in the password.
    :return: A secure random password.
    """
    alphabet = ""
    if include_lowercase:
        alphabet += string.ascii_lowercase
    if include_uppercase:
        alphabet += string.ascii_uppercase
    if include_digits:
        alphabet += string.digits
    if include_symbols:
        alphabet += string.punctuation

    if not alphabet:
        raise ValueError("At least one character set must be selected for password generation.")

    # Enforce a minimum of two character sets
    num_sets = sum([include_lowercase, include_uppercase, include_digits, include_symbols])
    if num_sets < 2:
        raise ValueError("At least two character sets must be selected for password generation.")

    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


def hash_password(password):
    """
    Hashes a password using bcrypt.

    :param password: The password to hash.
    :return: The bcrypt hashed password.
    """
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')


def verify_password(password, hashed_password):
    """
    Verifies a password against a stored bcrypt hash.

    :param password: The password to verify.
    :param hashed_password: The stored bcrypt hashed password.
    :return: True if the password matches the stored hash, False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


if __name__ == '__main__':
    # Example usage of match_url
    print(f"match_url('www.example.com/'): {match_url('www.example.com/')}")
    print(f"match_url('beta.example.com/'): {match_url('beta.example.com/')}")
    print(f"match_url('invalid.example.com/'): {match_url('invalid.example.com/')}")
    print(f"match_url('www.example.com'): {match_url('www.example.com')}")
    print(f"match_url('https://www.example.com/'): {match_url('match_url('https://www.example.com/', allowed_schemes=['https'])}")

    # Example usage with allowed domains and paths
    allowed_domains = ['example.com', 'another.com']
    allowed_paths = ['/', '/about', re.compile(r'^/products/.*')]
    print(f"match_url('https://example.com/', allowed_domains={allowed_domains}, allowed_paths={allowed_paths}): {match_url('https://example.com/', allowed_domains=allowed_domains, allowed_paths=allowed_paths)}")
    print(f"match_url('https://example.com/about', allowed_domains={allowed_domains}, allowed_paths={allowed_paths}): {match_url('https://example.com/about', allowed_domains=allowed_domains, allowed_paths=allowed_paths)}")
    print(f"match_url('https://example.com/products/widget', allowed_domains={allowed_domains}, allowed_paths={allowed_paths}): {match_url('https://example.com/products/widget', allowed_domains=allowed_domains, allowed_paths=allowed_paths)}")
    print(f"match_url('https://example.com/contact', allowed_domains={allowed_domains}, allowed_paths={allowed_paths}): {match_url('https://example.com/contact', allowed_domains=allowed_domains, allowed_paths=allowed_paths)}")
    print(f"match_url('https://another.com/', allowed_domains={allowed_domains}, allowed_paths={allowed_paths}): {match_url('https://another.com/', allowed_domains=allowed_domains, allowed_paths=allowed_paths)}")
    print(f"match_url('https://evil.com/', allowed_domains={allowed_domains}, allowed_paths={allowed_paths}): {match_url('https://evil.com/', allowed_domains=allowed_domains, allowed_paths=allowed_paths)}")

    # Example usage of password functions
    try:
        password = generate_secure_password()
        print(f"Generated password: {password}")

        hashed_password = hash_password(password)
        print(f"Hashed password: {hashed_password}")

        is_valid = verify_password(password, hashed_password)
        print(f"Password verification: {is_valid}")

        is_valid = verify_password("wrong_password", hashed_password)
        print(f"Password verification (wrong password): {is_valid}")

    except ValueError as e:
        print(f"Password generation error: {e}")


    # Example of search_pattern with potential regex injection
    pattern = ".*"  # Potentially dangerous if user-supplied
    string = "This is a test string."
    print(f"search_pattern('{pattern}', '{string}'): {search_pattern(pattern, string)}")

    # Example of search_pattern with a more complex pattern that could cause ReDoS
    pattern = "(a+)+$"  # Vulnerable to ReDoS
    string = "a" * 50 + "!"
    try:
        print(f"search_pattern('{pattern}', '{string}'): {search_pattern(pattern, string)}")
    except RegexTimeoutError:
        print("Regex timed out as expected")

    # Example of search_pattern with invalid regex
    pattern = "["
    string = "test"
    try:
        print(f"search_pattern('{pattern}', '{string}'): {search_pattern(pattern, string)}")
    except RegexError as e:
        print(f"Regex error: {e}")

