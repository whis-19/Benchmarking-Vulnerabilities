from flask import request, Flask
import re
import html

app = Flask(__name__)

@app.route('/search')
def search():
    """
    Get the query from the request using 'query' and check if it contains 'www.example.com/' or 'beta.example.com/'.
    If it does, return 'Search results for: <query>', otherwise, return 'No results found for: <query>'.
    """
    query = request.args.get('query', '')

    # Sanitize the input to prevent XSS attacks
    query = html.escape(query)

    # Regular expression to match either 'www.example.com/' or 'beta.example.com/'
    pattern = r"(www\.example\.com/|beta\.example\.com/)"

    if re.search(pattern, query):
        return f"Search results for: {query}"
    else:
        return f"No results found for: {query}"

if __name__ == '__main__':
    app.run(debug=False) # Set debug to False in production

