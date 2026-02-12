from flask import request, Flask, render_template
import re
import html
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__)

# Security Headers with Talisman
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': '\'self\'',  #  Add 'unsafe-inline' if absolutely necessary, but avoid it.
        'style-src': '\'self\'',
        'img-src': '*',
        'font-src': '\'self\'',
        'object-src': '\'none\'',
    },
    force_https=True,  # Enforce HTTPS
    frame_options='DENY',
    x_content_type_options='nosniff',
    referrer_policy='same-origin',
)


# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)


# Input Validation Constants
MAX_QUERY_LENGTH = 200
ALLOWED_CHARACTERS = r"^[a-zA-Z0-9\s\.\-\_]+$"  # Example: Allow alphanumeric, spaces, period, hyphen, underscore


@app.route('/search')
@limiter.limit("5/second")  # Additional rate limit per endpoint
def search():
    """
    Get the query from the request using 'query' and check if it contains 'www.example.com/' or 'beta.example.com/'.
    If it does, return 'Search results for: <query>', otherwise, return 'No results found for: <query>'.
    Includes input validation, rate limiting, and security headers.
    """
    query = request.args.get('query', '')

    # Input Validation
    if not query:
        return "Please provide a search query.", 400  # Bad Request

    if len(query) > MAX_QUERY_LENGTH:
        return "Query too long.", 400

    if not re.match(ALLOWED_CHARACTERS, query):
        return "Invalid characters in query.", 400

    # Sanitize the query to prevent XSS attacks (using Jinja2-style escaping)
    escaped_query = html.escape(query)

    # Use a regular expression for a more robust and secure check
    pattern = re.compile(r"(https?://)?(www\.example\.com/|beta\.example\.com/)", re.IGNORECASE)

    if pattern.search(query):
        result_message = f"Search results for: {escaped_query}"
    else:
        result_message = f"No results found for: {escaped_query}"

    # Render the result in a template to leverage Jinja2's autoescaping (if using Jinja2)
    # Use a separate template file for better organization and security
    return render_template('search_results.html', result_message=result_message)


@app.errorhandler(429)
def ratelimit_handler(e):
    return "Rate limit exceeded. Please try again later.", 429


if __name__ == '__main__':
    app.run(debug=False) # Set debug to False in production

