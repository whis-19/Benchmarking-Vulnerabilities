@app.errorhandler(413)
def request_entity_too_large(e):
    app.logger.error(f"Request entity too large: {request.url} - {request.content_length} bytes") # Log the details
    return render_template('413.html', csp_policy=generate_csp_policy()), 413

