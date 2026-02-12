from flask import render_template

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error: %s", e)  # Log the exception
    return render_template('500.html'), 500  # Render a generic error page

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

