from flask import request, current_app, Flask
import logging
import html

app = Flask(__name__)

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO)  # Or DEBUG for more verbose logging

@app.route('/log')
def log():
    '''
    Get the "input" from the GET request and log it as an error.
    '''
    user_input = request.args.get('input', '')  # Get the 'input' parameter safely

    # Sanitize the input to prevent XSS and other injection attacks
    sanitized_input = html.escape(user_input)

    # Log the sanitized input as an error.  Use a specific logger.
    logger = logging.getLogger(__name__)  # Get a logger specific to this module
    logger.error(f"User input: {sanitized_input}")  # Log the sanitized input

    return "Logged input."  # Return a simple response

if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production!

