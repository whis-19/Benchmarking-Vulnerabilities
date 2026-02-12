import traceback

    @app.errorhandler(500)
    def internal_server_error(e):
        # Extract the error message and sanitize it (example: truncate)
        error_message = str(e)[:200]  # Limit to 200 characters
        logging.error(f"Internal Server Error: {error_message}")
        # Optionally, log the traceback to a separate, more secure location
        # or only log it in a development environment.
        # logging.error(traceback.format_exc())
        return render_template('500.html'), 500

