import re
import urllib.parse
import html
import logging

# Configure logging (replace with your actual logging setup)
logging.basicConfig(level=logging.INFO)

ALLOWED_DOMAINS = ["www.example.com", "beta.example.com"]
ALLOWED_SCHEMES = {"http", "https"}  # Use a set for faster lookups
ALLOWED_PATH_REGEX = r"^/search.*"  # Example: Allow paths starting with /search

class InvalidQueryError(Exception):
    """Custom exception for invalid queries."""
    pass


def search(query):
    '''
    Check if it contains 'www.example.com/' or 'beta.example.com/'.

    :param query: The query to be checked
    :raises InvalidQueryError: If the query is invalid.
    :return: 'Search results for: <query>' if the query is valid.
    '''

    try:
        if not isinstance(query, str):
            raise InvalidQueryError("Query must be a string.")

        # Attempt to parse the query as a URL
        parsed_url = urllib.parse.urlparse(query)

        # Check if the scheme (e.g., http, https) is present.
        if not parsed_url.scheme:
            #  Consider raising an error here instead of defaulting to http.
            #  Forcing the user to specify the scheme can be more secure.
            # raise InvalidQueryError("Scheme (http or https) must be specified.")
            parsed_url = urllib.parse.urlparse("http://" + query)  # Default to http

        # Extract the hostname and scheme
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme
        path = parsed_url.path

        # Validate the hostname and scheme
        if hostname not in ALLOWED_DOMAINS:
            raise InvalidQueryError(f"The domain '{hostname}' is not allowed. Please use one of the following: {', '.join(ALLOWED_DOMAINS)}.")
        if scheme not in ALLOWED_SCHEMES:
            raise InvalidQueryError(f"The scheme '{scheme}' is not allowed. Please use one of the following: {', '.join(ALLOWED_SCHEMES)}.")

        # Validate the path (optional)
        if not re.match(ALLOWED_PATH_REGEX, path):
            raise InvalidQueryError(f"The path '{path}' is not allowed.  It must match the pattern: {ALLOWED_PATH_REGEX}")


        # Escape the query for safe display in HTML
        escaped_query = html.escape(query)
        return f"Search results for: {escaped_query}"


    except urllib.parse.ParseError as e:
        # If parsing as a URL fails, treat it as a simple string and disallow metacharacters
        #  WARNING:  This fallback behavior could be exploited.  Consider removing it.
        if re.search(r"[\.\*\+\?\^\$\{\}\[\]\\\(\)\|]", query):
            raise InvalidQueryError("Query contains disallowed metacharacters.")
        else:
            escaped_query = html.escape(query)
            return f"Search results for: {escaped_query}"
    except ValueError as e:  # Catch specific parsing errors
        raise InvalidQueryError(f"Invalid URL: {e}") from e
    except TypeError as e:
        raise InvalidQueryError(f"Invalid input type: {e}") from e
    except InvalidQueryError as e:
        # Re-raise our custom exception
        raise
    except Exception as e:
        logging.exception("Unexpected error during search:")  # Log the full exception
        raise  # Re-raise the exception to avoid masking errors


# Example usage (demonstrating error handling)
if __name__ == '__main__':
    try:
        result = search("www.example.com/search?q=test")
        print(result)

        result = search("malicious.com")  # Example of an invalid domain
        print(result)

        result = search("ftp://www.example.com") # Example of an invalid scheme
        print(result)

        result = search("www.example.com/admin") # Example of an invalid path

        print(result)

    except InvalidQueryError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

