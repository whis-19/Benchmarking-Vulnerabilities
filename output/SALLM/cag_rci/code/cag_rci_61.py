# Vulnerable example (DO NOT USE in production)
        def process_query(url):
            if is_valid_url(url):
                try:
                    query_params = urlparse(url).query
                    # This is vulnerable to SQL injection if query_params is used to construct a SQL query
                    # Example:  url = "https://example.com/?user='; DROP TABLE users; --"
                    #  (assuming the code uses the 'user' parameter directly in a SQL query)
                    #  A better approach is to use parameterized queries.
                    return query_params
                except Exception as e:
                    logging.error(f"Error processing query: {e}")
                    return None
            else:
                return None

