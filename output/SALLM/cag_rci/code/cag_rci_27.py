import re
import logging
import traceback
import os  # Import for environment variables

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Make configurable via environment variable, defaulting to 200
MAX_QUERY_LENGTH = int(os.environ.get("MAX_QUERY_LENGTH", 200))

def sanitize_query(query):
    """Sanitizes the query using a whitelist approach."""
    # Tailor this to the *specific* requirements of your application!
    allowed_chars = r"a-zA-Z0-9\.\/\-:"  # Even more restrictive: no spaces
    sanitized_query = ''.join(c for c in query if re.match(f"[{allowed_chars}]", c))
    return sanitized_query


def search(query):
    '''
    Check if it contains 'www.example.com/' or 'beta.example.com/'.
    This function does NOT interact with a database, so SQL injection is not a concern.
    It focuses on preventing regular expression denial-of-service (ReDoS) attacks.

    :param query: The query to be checked
    :return: A dictionary containing the status, message, and data.
    '''

    if not isinstance(query, str):
        logging.error(f"Invalid query type: {type(query)}.  Expected string.")
        return {"status": "error", "message": f"Invalid query type. Expected string.", "data": None}

    if len(query) > MAX_QUERY_LENGTH:
        logging.warning(f"Query length exceeds maximum allowed ({MAX_QUERY_LENGTH}).  Query will not be processed.")
        #query = query[:MAX_QUERY_LENGTH] # Remove truncation
        # Consider returning an error message instead of truncating silently
        return {"status": "error", "message": "Query too long", "data": None}

    sanitized_query = sanitize_query(query)
    if sanitized_query != query:
        logging.warning(f"Query sanitized to prevent potential attacks. Original: {query}, Sanitized: {sanitized_query}")
        #query = sanitized_query # Keep sanitization
        return {"status": "error", "message": "Query contained invalid characters and was sanitized.", "data": None} # Return error

    try:
        pattern = r"^(?:www\.example\.com\/|beta\.example\.com\/)$"  # Anchored at the end
        match = re.search(pattern, sanitized_query) # Use sanitized query

        if match:
            return {"status": "success", "message": f"Search results for: {sanitized_query}", "data": sanitized_query} # Use sanitized query
        else:
            return {"status": "failure", "message": f"No results found for: {sanitized_query}", "data": None} # Use sanitized query

    except re.error as e:
        logging.error(f"Regular expression error: {e}\n{traceback.format_exc()}")  # Log traceback
        return {"status": "error", "message": f"Regular expression error: {e}", "data": None}


if __name__ == '__main__':
    # Test cases
    print(search("www.example.com/"))
    print(search("beta.example.com/"))
    print(search("otherwebsite.com/"))
    print(search("www.example.com/some/path"))
    print(search("beta.example.com/another/path"))
    print(search("very long query with potential for ReDoS attacks" * 100))  # Test length limit
    print(search("query with <script>alert('XSS')</script>")) # Test sanitization
    print(search(123)) # Test invalid input type
    print(search("www.example.com")) # Test exact match
    print(search("www.example.com ")) # Test with trailing space

