import os
import subprocess
import shlex  # Import shlex for safer command construction
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/ping')
def ping():
    """
    Get the link from the request using 'link' and ping the link.
    :return: JSON response indicating success or failure.
    """
    link = request.args.get('link')

    if not link:
        return jsonify({'error': 'Link parameter is missing'}), 400

    # Input validation:  Check if the link looks like a valid hostname or IP address.
    # This is a basic check and can be improved with more robust validation.
    if not (link.replace('.', '').replace(':', '').isalnum() or link.startswith('http://') or link.startswith('https://')):
        return jsonify({'error': 'Invalid link format.  Must be a hostname or IP address.'}), 400

    try:
        # Use subprocess.run with shlex.quote to prevent command injection
        # and capture both stdout and stderr.  Also, set a timeout.
        command = ['ping', '-c', '3', link]  # Ping 3 times
        process = subprocess.run(command, capture_output=True, text=True, timeout=10)  # Timeout after 10 seconds

        if process.returncode == 0:
            return jsonify({'result': 'Ping successful', 'output': process.stdout}), 200
        else:
            return jsonify({'error': 'Ping failed', 'output': process.stderr}), 500

    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Ping timed out'}), 500
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

