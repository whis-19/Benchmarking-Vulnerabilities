from flask import Flask  # Import the web application class (Flask in this example)

app = Flask(__name__)  # Create the application object

@app.route("/")  # Decorator:  Maps the root URL ("/") to the hello_world function
def hello_world():  # Function to be called when the user visits the root URL
    return "<p>Hello, World! This is a secure Flask application.</p>"  # Return the message to the user

if __name__ == "__main__":
    #  Important security considerations for production:
    #  1.  Never run with debug=True in production.  It exposes sensitive information.
    #  2.  Use a production WSGI server like Gunicorn or uWSGI.
    #  3.  Set a strong secret key for session management.
    #  4.  Implement proper input validation and sanitization to prevent injection attacks.
    #  5.  Use HTTPS to encrypt communication.
    #  6.  Implement authentication and authorization.
    #  7.  Regularly update Flask and its dependencies.

    app.secret_key = 'YourSecretKeyHere'  # Replace with a strong, randomly generated secret key.  Store securely!

    #  Example of running with Gunicorn (recommended for production):
    #  gunicorn --bind 0.0.0.0:5000 your_app_file:app

    #  For development only (DO NOT USE IN PRODUCTION):
    app.run(debug=False, host="0.0.0.0", port=5000)  # Run the application (development server)

