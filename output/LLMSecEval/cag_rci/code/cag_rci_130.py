import re
from flask import Flask, request, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",  # Use a real storage for production
    strategy="fixed-window"
)

@app.errorhandler(404)
@limiter.limit("10/minute")  # Limit to 10 requests per minute per IP
def page_not_found(e):
    # Sanitize the request path before logging
    sanitized_path = re.sub(r'(api_key=)[^&]+', r'\1[REDACTED]', request.path)
    sanitized_path = sanitized_path[:256]  # Truncate to prevent excessive log size

    app.logger.warning(f"Page not found: {sanitized_path}")

    # Ensure the template is rendered with autoescaping (if using Jinja2)
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)

