import json
import logging
#from jsonschema import validate  # Import if you want to validate the schema
#from jsonschema import FormatChecker
# CSP Report Schema (Example - adapt to your needs)
csp_report_schema = {
    "type": "object",
    "properties": {
        "document-uri": {"type": "string", "format": "uri"},  # Validate URI format
        "blocked-uri": {"type": "string", "format": "uri"},  # Validate URI format
        "effective-directive": {"type": "string", "enum": ["default-src", "script-src", "style-src", "img-src", "connect-src", "font-src", "object-src", "media-src", "frame-src", "sandbox", "report-uri", "child-src", "form-action", "frame-ancestors", "plugin-types", "base-uri", "report-to", "worker-src", "manifest-src", "prefetch-src", "navigate-to"]}, # Enum of valid directives
        "violated-directive": {"type": "string"},
        "original-policy": {"type": "string"},
        "disposition": {"type": "string", "enum": ["enforce", "report"]},
    },
    "required": ["document-uri", "effective-directive", "violated-directive", "original-policy", "disposition"]
}


@app.route("/csp-report", methods=['POST'])
def csp_report():
    try:
        report = request.get_json()

        # Validate the report (optional)
        # try:
        #     validate(instance=report, schema=csp_report_schema, format_checker=FormatChecker())
        # except ValidationError as e:
        #     app.logger.warning(f"Invalid CSP Report: {e}")
        #     return '', 400  # Bad Request

        # Log only essential information, redact sensitive parts
        document_uri = report.get('document-uri', 'N/A')
        effective_directive = report.get('effective-directive', 'N/A')
        # Truncate blocked-uri to prevent excessive logging of sensitive URLs
        blocked_uri = report.get('blocked-uri', 'N/A')
        if blocked_uri != 'N/A':
            # Example: Hash the path and query parameters, keep the domain
            from urllib.parse import urlparse
            parsed_uri = urlparse(blocked_uri)
            hashed_path_query = hash(parsed_uri.path + "?" + parsed_uri.query)  # Simple hash - use a proper cryptographic hash in production
            blocked_uri = f"{parsed_uri.scheme}://{parsed_uri.netloc}/[HASHED_PATH_QUERY: {hashed_path_query}]"


        app.logger.warning(f"CSP Violation: document-uri={document_uri}, effective-directive={effective_directive}, blocked-uri={blocked_uri}")

        # Or, use structured logging:
        # app.logger.warning("CSP Violation", extra={
        #     "document_uri": document_uri,
        #     "effective_directive": effective_directive,
        #     "blocked_uri": blocked_uri
        # })


        return '', 204

    except Exception as e:
        app.logger.error(f"Error processing CSP report: {e}")
        return '', 500  # Internal Server Error


# Example CSRF Protection (using Flask-WTF)
# from flask_wtf.csrf import CSRFProtect
# csrf = CSRFProtect(app)  # Enable CSRF protection

# Example Rate Limiting (using Flask-Limiter)
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]
# )
# @app.route("/csp-report", methods=['POST'])
# @limiter.limit("10/minute") # Example: Limit to 10 requests per minute
# def csp_report():
#     # ... your code ...

# Consider Asynchronous Processing (using Celery)
# @celery.task
# def process_csp_report(report_data):
#     # ... your CSP report processing logic ...

# @app.route("/csp-report", methods=['POST'])
# def csp_report():
#     report = request.get_json()
#     process_csp_report.delay(report) # Send to Celery task queue
#     return '', 204

