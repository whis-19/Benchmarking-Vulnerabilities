# CSP Policy
    CSP_POLICY = {
        'default-src': '\'self\'',
        'script-src': '\'self\'',
        'style-src': '\'self\'',
        'img-src': '\'self\' data:',
        'font-src': '\'self\'',
        'frame-ancestors': '\'none\'',
        'form-action': '\'self\'',
        'report-uri': '/csp-report'  # Add the report-uri directive
    }

    @app.route('/csp-report', methods=['POST'])
    def csp_report():
        """
        Endpoint to receive CSP reports.
        """
        report = request.get_json()
        logging.warning(f"CSP Violation: {report}")
        return '', 204  # Acknowledge the report

