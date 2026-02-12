import re
from flask import Flask, request, Response
import html
import logging
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach
import uuid  # Import uuid

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Talisman (for security headers)
talisman = Talisman(app, content_security_policy="default-src 'self'", x_content_type_options='nosniff') # Added nosniff

# Initialize Limiter (for rate limiting)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Example rate limit
)


@app.route('/filter_script_tags', methods=['POST'])
@talisman.content_security_policy("default-src 'self'")  # Example CSP
@limiter.limit("10/minute")  # Example rate limit
def filterScriptTags():
    """
    Get content from the request using 'content' and remove script tags from it.
    This function is designed to mitigate XSS vulnerabilities.
    """
    try:
        content = request.form.get('content', '')  # Use request.form for POST requests

        # Input validation:  Check if content is a string
        if not isinstance(content, str):
            logger.warning("Invalid input: Content must be a string.")
            return Response("Invalid input: Content must be a string.", status=400)

        # Input validation: Limit input size to prevent DoS
        if len(content) > 10000:  # Example limit: 10KB
            logger.warning("Input too large.  Possible DoS attempt.")
            return Response("Input too large.", status=400)

        # Input validation: Example regex validation (adjust as needed)
        if not re.match(r"^[a-zA-Z0-9\s]*$", content):
            logger.warning("Invalid input: Content contains invalid characters.")
            return Response("Invalid input: Content contains invalid characters.", status=400)


        # Sanitize input: Use Bleach to sanitize HTML
        allowed_tags = ['b', 'i', 'p']  # Example: Only allow bold, italic, and paragraph tags
        allowed_attributes = {}  # Or specify attributes if needed, e.g., {'p': ['class']}
        sanitized_content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes, strip=True)


        # Return the filtered content
        return Response(sanitized_content, mimetype='text/plain')  # Set mimetype for security

    except Exception as e:
        request_id = str(uuid.uuid4())  # Generate a unique ID for the request
        logger.exception(f"An error occurred (Request ID: {request_id}): {e}")
        return Response(f"An error occurred while processing the request.  Please provide Request ID: {request_id} to support.", status=500)


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

