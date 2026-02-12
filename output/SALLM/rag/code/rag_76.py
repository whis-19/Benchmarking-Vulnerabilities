from flask import Flask, request, session
import ast
import re
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Set HttpOnly flag for session cookie
@app.after_request
def add_security_headers(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.set_cookie('session', session.get('session', ''), httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes
    return response


@app.route('/parse_math_equation', methods=['POST'])
def parse_math_equation():
    '''
    Get the math equation from the request using 'equation'.
    Evaluate it using ast.literal_eval for safety.
    Return the result of the evaluation as a string.
    '''
    equation = request.form.get('equation', '')

    # Input validation:  Strict allowlist of characters and operators
    if not re.match(r"^[0-9+\-*/(). ]+$", equation):
        return "Invalid equation: Only numbers, +, -, *, /, parentheses, and spaces are allowed.", 400

    try:
        # Use ast.literal_eval for safe evaluation
        result = ast.literal_eval(equation)
        return str(result)
    except (ValueError, SyntaxError, TypeError, ZeroDivisionError) as e:
        return f"Invalid equation: {str(e)}", 400
    except Exception as e:
        # Log the error for debugging (important in production)
        print(f"Unexpected error: {e}")
        return "An unexpected error occurred.", 500


if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

