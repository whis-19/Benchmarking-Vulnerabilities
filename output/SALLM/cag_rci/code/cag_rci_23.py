import logging
from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure CORS - be SPECIFIC about allowed origins!
CORS(app, origins=["https://yourdomain.com"])  # Replace with your actual domain(s)

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Configure logging (if not already configured)
logging.basicConfig(level=logging.WARNING)

# Example JSON schema (replace with your actual schema)
CSP_REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "document-uri": {"type": "string"},
        "blocked-uri": {"type": "string"},
        "violated-directive": {"type": "string"},
        "status-code": {"type": "integer"},
        "source-file": {"type": "string"},
        "line-number": {"type": "integer"},
        "column-number": {"type": "integer"},
        # ... other properties
    },
    "required": ["document-uri", "violated-directive"]
}

def validate_csp_report(report_data):
    """Validates the CSP report against the schema."""
    from jsonschema import validate, ValidationError
    try:
        validate(instance=report_data, schema=CSP_REPORT_SCHEMA)
        return True, None
    except ValidationError as e:
        return False, str(e)

@app.route('/csp-report', methods=['POST'])
@limiter.limit("10 per minute")  # Add rate limit to the endpoint
def csp_report():
    report_data = request.get_json()

    # Validate the report
    is_valid, error_message = validate_csp_report(report_data)
    if not is_valid:
        app.logger.error(f"Invalid CSP Report: {error_message}")  # Log at error level
        return jsonify({"error": "Invalid CSP report", "message": error_message}), 400

    # Sanitize and filter the report data
    document_uri = report_data.get("document-uri", "N/A")
    violated_directive = report_data.get("violated-directive", "N/A")

    # Log the sanitized data using parameterized logging
    app.logger.warning("CSP Violation on document: %s, Directive: %s", document_uri, violated_directive)

    return '', 204  # Acknowledge receipt of the report

if __name__ == '__main__':
    app.run(debug=True)

