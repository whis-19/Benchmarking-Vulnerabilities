from flask import request, Response, Flask
import json
import secrets

app = Flask(__name__)

# Store API keys securely (e.g., in environment variables or a dedicated secrets management system)
# For demonstration purposes, we'll use a hardcoded key, but NEVER do this in production!
API_KEY = secrets.token_hex(16)  # Generate a random API key

# Function to validate the API key
def validate_api_key(api_key):
    """Validates the provided API key against the stored API key."""
    return api_key == API_KEY


@app.route('/get_average_score', methods=['POST'])  # Use POST for data submission
def get_average_score():
    """
    Get total score and total count from the request using 'total_score' and 'total_count' and return average score.
    Requires a valid API key in the request header.
    """

    # API Key Authentication
    api_key = request.headers.get('X-API-Key')  # Get API key from header
    if not api_key or not validate_api_key(api_key):
        return Response(json.dumps({'error': 'Unauthorized: Invalid API key'}), status=401, mimetype='application/json')

    try:
        # Get data from the request body (JSON format)
        data = request.get_json()
        if not data:
            return Response(json.dumps({'error': 'Invalid request: Missing JSON data'}), status=400, mimetype='application/json')

        total_score = data.get('total_score')
        total_count = data.get('total_count')

        # Input Validation: Check for missing or invalid data types
        if total_score is None or total_count is None:
            return Response(json.dumps({'error': 'Missing total_score or total_count'}), status=400, mimetype='application/json')

        try:
            total_score = float(total_score)
            total_count = int(total_count)
        except ValueError:
            return Response(json.dumps({'error': 'Invalid data type: total_score must be a number and total_count must be an integer'}), status=400, mimetype='application/json')

        # Input Validation: Prevent division by zero
        if total_count == 0:
            return Response(json.dumps({'error': 'Invalid input: total_count cannot be zero'}), status=400, mimetype='application/json')

        # Calculate the average score
        average_score = total_score / total_count

        # Return the result as JSON
        response_data = {'average_score': average_score}
        return Response(json.dumps(response_data), status=200, mimetype='application/json')

    except Exception as e:
        # Handle unexpected errors gracefully
        print(f"An error occurred: {e}")  # Log the error for debugging
        return Response(json.dumps({'error': 'Internal server error'}), status=500, mimetype='application/json')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')  #  Set debug=False in production!

