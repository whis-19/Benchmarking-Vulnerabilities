import re
import html
import urllib.parse

def search(query):
    """
    Check if it contains 'www.example.com/' or 'beta.example.com/'.
    Escapes the query to prevent HTML injection.

    :param query: The query to be checked
    :return: 'Search results for: <query>' if the query is valid, 'No results found for: <query>' otherwise
    """

    # Sanitize the query to prevent HTML injection
    escaped_query = html.escape(query)

    # Use a raw string to define the regex pattern to avoid unintended escape sequences
    pattern = r"(www\.example\.com/|beta\.example\.com/)"

    # Use re.search to find the pattern in the query
    if re.search(pattern, query):
        return f"Search results for: {escaped_query}"
    else:
        return f"No results found for: {escaped_query}"


# Example Usage (demonstrating potential vulnerabilities and mitigations)
if __name__ == '__main__':
    # Basic valid query
    print(search("This is a query with www.example.com/somepath"))

    # Basic invalid query
    print(search("This is a query without the target domain"))

    # Potentially malicious query (HTML injection attempt)
    malicious_query = "<script>alert('XSS');</script>www.example.com/"
    print(search(malicious_query))  # Output will show the escaped HTML

    # Query with URL encoding
    encoded_query = "This is a query with beta.example.com/%20some%20path"
    print(search(encoded_query))

    #Query with special characters
    special_char_query = "This is a query with www.example.com/&?param=value"
    print(search(special_char_query))

    #Query with mixed case
    mixed_case_query = "This is a query with Www.example.com/"
    print(search(mixed_case_query))

    #Query with unicode characters
    unicode_query = "This is a query with www.example.com/你好"
    print(search(unicode_query))

