from flask import Flask, redirect, request, make_response, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from urllib.parse import urlparse
import re
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

ALLOWED_DOMAINS = ["example.com", "trusted.com"]  # Consider explicitly listing all allowed domains instead of using wildcards.  Using wildcards requires extremely robust URL sanitization. It's generally safer to explicitly list all allowed domains.

class RedirectForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired()])
    submit = SubmitField('Redirect')

@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # IMPORTANT: Customize the Content Security Policy (CSP) below!
    # This is a *very basic* example and *must* be adapted to your application's needs.
    # For example:
    #   - If you use a CDN for JavaScript or CSS, you need to add it to script-src and style-src.
    #   - If you use Google Fonts, you need to add fonts.googleapis.com to font-src.
    #   - If you use images from a specific domain, add it to img-src.
    # This CSP is a starting point and *must* be customized to your application's specific requirements.
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # Consider adding Referrer-Policy and Feature-Policy (Permissions Policy) headers as well.
    return response

@app.route('/', methods=['GET', 'POST'])
def index():
    form = RedirectForm()
    if form.validate_on_submit():
        target = form.url.data

        try:
            parsed_url = urlparse(target)
            hostname = parsed_url.hostname
            scheme = parsed_url.scheme

            if not hostname:
                return "Error: Invalid URL - No hostname", 400

            if scheme not in ['http', 'https']:
                return "Error: Invalid URL - Scheme must be http or https", 400

            domain_parts = hostname.split('.')
            top_level_domain = domain_parts[-1]
            second_level_domain = domain_parts[-2]
            base_domain = second_level_domain + "." + top_level_domain

            if base_domain not in ALLOWED_DOMAINS:
                return "Error: Invalid domain", 400

            sanitized_target = re.sub(r'[^-a-zA-Z0-9:/.%#?&=]', '', target)

            if sanitized_target != target:
                return "Error: Invalid characters in URL", 400

            response = make_response(redirect(sanitized_target, code=302))
            response.headers['Content-Type'] = 'text/html; charset=utf-8'
            return response

        except Exception as e:
            print(f"Error parsing URL: {e}")
            return "Error: Invalid URL", 400

    return render_template('index.html', form=form)

if __name__ == '__main__':
    # IMPORTANT: Disable debug mode in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

