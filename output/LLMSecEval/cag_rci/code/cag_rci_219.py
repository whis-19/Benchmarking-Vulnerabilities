from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,  # Limit by IP address
    default_limits=["200 per day", "50 per hour"]  # Default limits
)

@app.route("/upload", methods=['POST'])
@limiter.limit("10 per minute")  # Example: Limit uploads to 10 per minute
def upload_file():
    """Handles file uploads with security checks."""
    # ... your upload logic ...
    return "Upload successful"  # Or your actual response

