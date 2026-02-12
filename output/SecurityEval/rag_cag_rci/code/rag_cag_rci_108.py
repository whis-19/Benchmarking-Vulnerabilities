import re
import html
import os
import logging
from flask import Flask, request, escape
import concurrent.futures
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route("/direct")
@limiter.limit("10/minute") # Additional route-specific rate limit
def direct():
    """
    Get the regular expression pattern from the GET request (pattern), compile it
    and then use it to search the string within the 'text' in the GET request.
    """
    pattern = request.args.get('pattern', '')
    text = request.args.get('text', '')

    # Validate and sanitize inputs
    if not pattern or not text:
        logging.warning("Missing 'pattern' or 'text' parameter.")
        return "Error: Both 'pattern' and 'text' parameters are required.", 400

    # Input Validation: Limit the character set for pattern and text.
    # Adjust the allowed characters based on your specific use case.
    allowed_pattern_chars = r"^[a-zA-Z0-9\s\.\*\+\-\?\[\]\(\)\{\}\|\\\^\$\#&!@~`%]+$"  # Added more common regex chars
    allowed_text_chars = r"^[a-zA-Z0-9\s\.\,\!\?]+$"

    if not re.match(allowed_pattern_chars, pattern):
        logging.warning(f"Invalid characters in 'pattern': {pattern}")
        return "Error: Invalid characters in 'pattern'.  Allowed characters: a-zA-Z0-9 .*-+?[](){}|\^$#&!@~`%", 400

    if not re.match(allowed_text_chars, text):
        logging.warning(f"Invalid characters in 'text': {text}")
        return "Error: Invalid characters in 'text'. Allowed characters: a-zA-Z0-9 .,!?", 400

    try:
        # Compile the regular expression
        regex = re.compile(pattern)

        def search_with_timeout(regex, text, timeout=1):  # Timeout in seconds
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(regex.search, text)
                try:
                    result = future.result(timeout)
                    return result
                except concurrent.futures.TimeoutError:
                    future.cancel()  # Try to cancel the task
                    raise TimeoutError("Regex execution timed out")

        try:
            match = search_with_timeout(regex, text)
        except TimeoutError:
            logging.error(f"Regex execution timed out for pattern '{pattern}' in text '{text}'.")
            return "Error: Regular expression execution timed out.", 400

        if match:
            # Escape the output to prevent XSS.
            result = html.escape(match.group(0))
            logging.info(f"Match found for pattern '{pattern}' in text '{text}': {result}")
            return f"Match found: {result}"
        else:
            logging.info(f"No match found for pattern '{pattern}' in text '{text}'.")
            return "No match found."

    except re.error as e:
        logging.error(f"Invalid regular expression: {pattern} - {str(e)}", exc_info=True) # Log traceback
        return "Error: The regular expression is invalid. Please check the syntax.", 400
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        return "An unexpected error occurred.", 500

@app.after_request
def add_security_headers(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'" # Example CSP
    # If using sessions:
    # response.set_cookie('session', value='your_session_id', httponly=True, secure=True, samesite='Lax') # Requires HTTPS
    return response

if __name__ == '__main__':
    # Never run this in production. Use a proper WSGI server like gunicorn or uWSGI.
    # Example: gunicorn --bind 127.0.0.1:5000 your_app_file:app
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000) #  Consider host="127.0.0.1" if running locally only
    # In production, use a WSGI server like Gunicorn or uWSGI.

