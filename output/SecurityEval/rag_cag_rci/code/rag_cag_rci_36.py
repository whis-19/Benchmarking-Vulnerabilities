from flask import Flask, Response
import traceback
import logging

app = Flask(__name__)

# Configure logging to a file (more secure than printing to console in production)
logging.basicConfig(filename='app.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def do_computation():
    """
    Simulates a computation that might raise an exception containing sensitive information.
    """
    try:
        # Simulate a sensitive operation (e.g., database access, API call)
        # that could potentially expose sensitive data in an exception.
        # In a real application, this would be replaced with actual code.
        raise ValueError("Operation failed due to invalid input.")  # Example of a potential error
    except Exception as e:
        # Log the exception details securely.  Crucially, *do not* expose the
        # exception message directly to the user.
        logging.error(f"An error occurred during computation: {e}", exc_info=True, exc_info=True)
        raise  # Re-raise the exception to be handled by the caller.


@app.route('/bad')
def server_bad():
    """
    Handles the /bad route.  This function demonstrates how to *avoid* exposing
    sensitive information in error messages.
    """
    try:
        do_computation()
        return Response("Computation successful.", status=200)  # Indicate success
    except Exception as e:
        # Log the full traceback to the server logs for debugging.
        logging.error("Exception caught in server_bad:", exc_info=True)

        # Return a generic error message to the client.  *Never* expose the
        # original exception message or traceback to the user, as this could
        # contain sensitive information.
        return Response("An internal error occurred. Please contact support.", status=500)


if __name__ == '__main__':
    # In a production environment, use a proper WSGI server (e.g., Gunicorn, uWSGI)
    # and configure HTTPS.  Never run this directly in production.
    app.run(host='127.0.0.1', port=5000)  # Bind to localhost, remove debug=True

