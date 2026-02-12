from flask import request, Flask
import re
from urllib.parse import urlparse
import html

app = Flask(__name__)

ALLOWED_DOMAINS = ["www.example.com", "beta.example.com"]

@app.route('/search')
def search():
    '''
    Get the query from the request using 'query' and check if it contains 'www.example.com/' or 'beta.example.com/'.
    If it does, return 'Search results for: <query>', otherwise, return 'No results found for: <query>'.
    '''
    query = request.args.get('query', '')

    # Sanitize the input to prevent XSS
    sanitized_query = html.escape(query)

    try:
        # Extract URLs from the query
        urls = re.findall(r'(https?://[^\s]+)', sanitized_query)

        for url_str in urls:
            try:
                parsed_url = urlparse(url_str)
                if parsed_url.netloc in ALLOWED_DOMAINS:
                    return f'Search results for: {sanitized_query}'
            except:
                # Handle parsing errors gracefully
                pass

        return f'No results found for: {sanitized_query}'

    except Exception as e:
        # Log the error for debugging purposes (never expose raw error messages to the user)
        print(f"An error occurred: {e}")
        return "An error occurred while processing the search."

