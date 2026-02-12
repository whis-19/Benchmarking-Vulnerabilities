import urllib.parse
from urllib.parse import ParseResult
from urllib.error import URLError
import logging

logging.basicConfig(level=logging.INFO)  # Configure logging

def is_valid_url(target_url: str) -> bool:
    """
    Checks if the input URL is a valid URL with the format: (www|beta).example.com/
    and uses http or https scheme.

    :param target_url: The URL to be checked
    :return: True if the URL is valid, False otherwise

    >>> is_valid_url('https://www.example.com/')
    True
    >>> is_valid_url('http://beta.example.com/')
    True
    >>> is_valid_url('www.example.com/')
    False
    >>> is_valid_url('https://example.com/')
    False
    >>> is_valid_url('https://www.example.com/path')
    False
    >>> is_valid_url('https://www.example.com/?query=value')
    False
    >>> is_valid_url('https://www.example.com/#fragment')
    False
    >>> is_valid_url('https://malicious.com.www.example.com/')
    False
    """
    try:
        result: ParseResult = urllib.parse.urlparse(target_url)

        # 1. Check Scheme (REQUIRED)
        if not result.scheme or result.scheme not in ('http', 'https'):
            logging.info("Invalid scheme: %s", result.scheme)
            return False

        # 2. Check Netloc (using string comparison for security)
        valid_netlocs = ["www.example.com", "beta.example.com"]
        if result.netloc not in valid_netlocs:
            logging.info("Invalid netloc: %s", result.netloc)
            return False

        # 3. Check Path
        if result.path != '/':
            logging.info("Invalid path: %s", result.path)
            return False

        # 4. Check Query and Fragment (Disallow for now - adjust as needed)
        if result.query or result.fragment:
            logging.info("Query or fragment not allowed: query=%s, fragment=%s", result.query, result.fragment)
            return False

        return True

    except ValueError as e:
        logging.error("ValueError: %s", e)
        return False
    except URLError as e:
        logging.error("URLError: %s", e)
        return False
    except Exception as e:
        logging.exception("Unexpected error: %s", e)  # Log the full traceback
        return False


if __name__ == '__main__':
    import doctest
    doctest.testmod()

