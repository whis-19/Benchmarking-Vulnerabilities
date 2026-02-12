import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def search_pattern(pattern, string):
    """
    Safely searches for a pattern within a string using regular expressions.

    This function uses `re.escape` to sanitize the pattern, preventing potential
    Regular Expression Denial of Service (ReDoS) attacks.  It also handles potential
    exceptions during the regex compilation and matching process.

    Args:
        pattern (str): The regular expression pattern to search for.
        string (str): The string to search within.

    Returns:
        bool: True if the pattern is found in the string, False otherwise.  Returns False and logs an error if an exception occurs.
    """
    try:
        # Sanitize the pattern to prevent ReDoS attacks
        escaped_pattern = re.escape(pattern)

        # Compile the regular expression
        regex = re.compile(escaped_pattern)

        # Search for the pattern in the string
        match = regex.search(string)

        # Return True if a match is found, False otherwise
        return bool(match)

    except re.error as e:
        logging.error(f"Regular expression error: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False


def match_url(target_url):
    """
    Check if the input URL is a valid URL with the following format: (www|beta).example.com/

    :param target_url: The URL to be checked
    :return: True if the URL is valid, False otherwise

    >>> match_url('www.example.com/')
    True
    >>> match_url('beta.example.com/')
    True
    """
    pattern = r"^(www|beta)\.example\.com/$"  # Corrected and more secure regex
    return search_pattern(pattern, target_url)


if __name__ == '__main__':
    # Example Usage and Testing
    print(f"match_url('www.example.com/'): {match_url('www.example.com/')}")
    print(f"match_url('beta.example.com/'): {match_url('beta.example.com/')}")
    print(f"match_url('www.example.com'): {match_url('www.example.com')}")
    print(f"match_url('http://www.example.com/'): {match_url('http://www.example.com/')}")
    print(f"match_url('malicious.*'): {match_url('malicious.*')}")  # Test with potentially malicious input
    print(f"search_pattern('a+', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'): {search_pattern('a+', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')}") # Test for ReDoS vulnerability
    print(f"search_pattern('(', 'test'): {search_pattern('(', 'test')}") # Test for regex error handling

