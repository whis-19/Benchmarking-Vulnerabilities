from flask import Flask, request
import logging
import html

logging.basicConfig(level=logging.INFO)  # Changed to INFO for production

app = Flask(__name__)

@app.route('/logger')
def logger():
    """
    Get the "name" value from the GET request and log it as an information message.
    Sanitizes the input to prevent XSS and other injection attacks.
    """
    name = request.args.get('name', '')

    # Sanitize the input to prevent XSS attacks
    sanitized_name = html.escape(name)

    # Log the sanitized name
    app.logger.info(f"Received name: {sanitized_name}")

    return f"Logged name: {sanitized_name}"


if __name__ == '__main__':
    #  Do NOT use debug=True in production.  It exposes sensitive information.
    #  Use a proper WSGI server like gunicorn or uWSGI for production deployments.
    app.run(debug=False, host='0.0.0.0', port=5000)

