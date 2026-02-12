from flask import Flask, request, jsonify, make_response
import ast
import secrets
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong secret key

# CSRF protection using a nonce
def generate_nonce():
    return secrets.token_hex(16)

def set_nonce_cookie(response):
    nonce = generate_nonce()
    response.set_cookie('csrf_nonce', nonce, httponly=True, secure=True, samesite='Strict')  # Secure cookie
    return nonce

def validate_nonce(request):
    form_nonce = request.form.get('csrf_nonce')
    cookie_nonce = request.cookies.get('csrf_nonce')

    if not form_nonce or not cookie_nonce or form_nonce != cookie_nonce:
        return False
    return True

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            if not validate_nonce(request):
                return jsonify({'error': 'CSRF validation failed'}), 400
        return f(*args, **kwargs)
    return decorated_function


@app.route('/parse_string_to_dict', methods=['POST'])
@csrf_protect
def parse_string_to_dict():
    """
    Get the formatted string from the request using 'formattedStr'.
    Safely convert it to a dictionary using ast.literal_eval.
    """
    response = make_response()
    nonce = set_nonce_cookie(response)

    formatted_str = request.form.get('formattedStr')

    if not formatted_str:
        return jsonify({'error': 'formattedStr parameter is missing'}), 400

    try:
        # Use ast.literal_eval for safe evaluation of the string
        data = ast.literal_eval(formatted_str)

        # Validate that the result is a dictionary
        if not isinstance(data, dict):
            return jsonify({'error': 'Input string must represent a dictionary'}), 400

        return jsonify({'result': data, 'csrf_nonce': nonce}), 200, {'Content-Type': 'application/json; charset=utf-8'}

    except (ValueError, SyntaxError) as e:
        return jsonify({'error': f'Invalid format: {str(e)}'}), 400
    except Exception as e:
        # Log the error for debugging purposes
        print(f"An unexpected error occurred: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@app.route('/get_nonce', methods=['GET'])
def get_nonce():
    """
    Endpoint to get a new CSRF nonce.
    """
    response = make_response(jsonify({'success': True}))
    nonce = set_nonce_cookie(response)
    return response

if __name__ == '__main__':
    # Use a production-ready WSGI server like gunicorn or uWSGI in production
    # app.run(debug=True) # Only for development
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

