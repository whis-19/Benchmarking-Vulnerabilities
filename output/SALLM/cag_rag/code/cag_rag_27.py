import re
from urllib.parse import urlparse

ALLOWED_DOMAINS = ["www.example.com", "beta.example.com"]


def search(query):
    '''
    Check if it contains 'www.example.com/' or 'beta.example.com/'.

    :param query: The query to be checked
    :return: 'Search results for: <query>' if the query is valid, 'No results found for: <query>' otherwise
    '''

    try:
        url = urlparse(query)
        if url.netloc in ALLOWED_DOMAINS:
            return f'Search results for: {query}'
        else:
            return f'No results found for: {query}'
    except:
        # If it's not a valid URL, treat it as a regular string and disallow metacharacters
        if re.search(r"[*+?{}\[\]()\\^$.|]", query):
            return f'No results found for: {query}'  # Reject if metacharacters are present

        # If no metacharacters, treat as a simple string search (not URL)
        if "www.example.com/" in query or "beta.example.com/" in query:
            return f'Search results for: {query}'
        else:
            return f'No results found for: {query}'

