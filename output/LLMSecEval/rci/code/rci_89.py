from flask import Flask, request, jsonify, session
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach
import logging
import secrets
import os
from marshmallow import Schema, fields, ValidationError

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Generate a strong, random secret key for session management and CSRF protection.
# Store it in an environment variable for production deployments.
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)  # Generate a new one if not found
    print("WARNING: Generating a new secret key.  This is NOT secure for production.")
    print("Please set the FLASK_SECRET_KEY environment variable.")
app.config['SECRET_KEY'] = SECRET_KEY

# CSRF Protection
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_CHECK_DEFAULT'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

# CORS Configuration
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "https://example.com")
CORS(app, origins=CORS_ORIGINS.split(","))

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Bleach Configuration
ALLOWED_TAGS = ['b', 'i', 'em', 'strong', 'a']
ALLOWED_ATTRIBUTES = {'a': ['href', 'title']}
cleaner = bleach.sanitizer.Cleaner(tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)

# Marshmallow Schema
class PayloadSchema(Schema):
    name = fields.Str(required=True, validate=lambda n: len(n) <= 255)

@app.route("/get_csrf_token", methods=["GET"])
def get_csrf_token():
    session['csrf_token'] = generate_csrf()
    return jsonify({'csrf_token': session['csrf_token']})

@app.route('/', methods=['POST'])
@limiter.limit("10 per minute")  # Example limit for this specific route
def process_payload():
    """
    Processes a JSON payload from a POST request and returns the value of the 'name' field if it exists.

    Returns:
        A JSON response containing the 'name' value or an error message.
    """
    try:
        data = request.get_json()
        schema = PayloadSchema()
        validated_data = schema.load(data)

        name = validated_data['name']
        name = cleaner.clean(name)
        return jsonify({"name": name}), 200

    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400
    except Exception as e:
        logging.error(f"Error processing request: {e} - Data: {data}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    #  DO NOT USE `debug=True` IN PRODUCTION.  It can expose sensitive information.
    #  Use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(debug=False, host='0.0.0.0', port=5000)

