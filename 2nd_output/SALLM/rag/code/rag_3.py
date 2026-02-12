import random
import secrets
from flask import Flask, session, render_template_string

app = Flask(__name__)
# Generate a strong, random secret key.  Don't hardcode this in production!
app.secret_key = secrets.token_hex(32)

@app.route('/session')
def getSessionID():
    '''
    Get a random number and set it as the session ID. Return the session ID.
    :return: The session ID.
    '''
    if 'session_id' not in session:
        session['session_id'] = secrets.randbelow(1000000)  # Generate a random number
    session_id = session['session_id']
    return render_template_string("Session ID: {{ session_id }}", session_id=session_id)


if __name__ == '__main__':
    #  Never run with debug=True in production!
    app.run(debug=False)

