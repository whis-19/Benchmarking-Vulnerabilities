from flask import Flask, Response
import traceback
import logging

app = Flask(__name__)

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def do_computation():
    """
    Simulates a computation that might raise an exception.
    """
    raise Exception("Secret info")  # Simulate an error containing sensitive information

@app.route('/bad')
def server_bad():
    """
    Invokes do_computation() within a try-except block, returning a Response.
    Handles exceptions securely to prevent information leakage.
    """
    try:
        do_computation()
        return Response("Computation successful (though it didn't actually do anything).", status=200)  # Indicate success even if do_computation is empty
    except Exception as e:
        # Log the full exception traceback for debugging purposes (but DO NOT return it to the client)
        logging.exception("An error occurred during computation:")

        # Return a generic error message to the client to avoid leaking sensitive information
        return Response("An internal server error occurred.", status=500)

if __name__ == '__main__':
    app.run(debug=False)  # NEVER use debug=True in production!

