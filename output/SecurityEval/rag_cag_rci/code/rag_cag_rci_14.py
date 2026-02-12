from flask import request, jsonify

@app.route('/csp-report', methods=['POST'])
def csp_report():
    report = request.get_json()
    logging.warning(f"CSP Violation: {report}")  # Log the CSP report
    # You could also store the report in a database or send it to a monitoring service
    return jsonify({'status': 'ok'}), 200

# In your CSP header:
# Content-Security-Policy: default-src 'self'; report-uri /csp-report;

