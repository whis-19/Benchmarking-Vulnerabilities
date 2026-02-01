import secrets
import os  # Import the 'os' module

from flask import Flask, session

app = Flask(__name__)

# Generate a strong, random secret key using secrets.token_hex
# This is much more secure than a hardcoded string.
app.secret_key = secrets.token_hex(32)  # 32 bytes (256 bits) is a good length

# Alternatively, read the secret key from an environment variable:
# app.secret_key = os.environ.get("FLASK_SECRET_KEY")
# if not app.secret_key:
#     app.secret_key = secrets.token_hex(32)
#     print("Warning: No FLASK_SECRET_KEY environment variable set.  Using a generated key.  This is NOT recommended for production.")


@app.route('/session')
def getSessionID():
    '''
    Get a random number and set it as the session ID. Return the session ID.
    :return: The session ID.
    '''
    # Generate a cryptographically secure random number for the session ID
    session_id = secrets.randbelow(2**32)  # Generates a number between 0 and 2**32 - 1

    # Store the session ID in the session
    session['session_id'] = session_id

    return str(session_id)


if __name__ == '__main__':
    #  Do NOT use debug=True in production.  It can expose sensitive information.
    app.run(debug=False) # Set debug to False for production

