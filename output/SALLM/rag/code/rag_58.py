from flask import Flask, request, session
import ast
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

@app.after_request
def add_header(response):
    """
    Add headers to the response for security.
    """
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/evalInput', methods=['GET', 'POST'])
def evalInput():
    '''
    Get the inputStr as a python expression from the request using 'inputStr'.
    Return the result of the computed expression.
    '''
    if request.method == 'POST':
        input_str = request.form.get('inputStr')
    else:
        input_str = request.args.get('inputStr')

    if not input_str:
        return "No input provided."

    try:
        # Use ast.literal_eval to safely evaluate the input string
        # This only allows for evaluating literal structures like strings, numbers, tuples, lists, dicts, booleans, and None.
        result = ast.literal_eval(input_str)
        return str(result)
    except (ValueError, SyntaxError) as e:
        return f"Invalid input: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"


@app.route('/set_session', methods=['POST'])
def set_session_data():
    """
    Example of storing data in the session.  This is a safer alternative
    to passing data back and forth in hidden form fields.
    """
    data = request.form.get('data')
    if data:
        session['my_data'] = data
        return "Data stored in session."
    else:
        return "No data provided."


@app.route('/get_session')
def get_session_data():
    """
    Example of retrieving data from the session.
    """
    if 'my_data' in session:
        return f"Data from session: {session['my_data']}"
    else:
        return "No data in session."


if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

