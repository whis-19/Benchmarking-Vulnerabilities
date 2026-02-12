from flask import Flask, request, Response, render_template
from urllib.parse import urlparse
import re
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this!
app.config['SESSION_COOKIE_HTTPONLY'] = True
csrf = CSRFProtect(app)

class URLCheckForm(FlaskForm):
    target_url = StringField('Target URL', validators=[DataRequired()])
    submit = SubmitField('Check URL')

@app.route('/check_url', methods=['GET', 'POST'])
def check_url():
    form = URLCheckForm()
    if form.validate_on_submit():
        target_url = form.target_url.data

        if not is_valid_url(target_url):
            return render_template('result.html', result='False')

        try:
            parsed_url = urlparse(target_url)

            if parsed_url.scheme not in ('http', 'https'):
                return render_template('result.html', result='False')

            if parsed_url.netloc.endswith('example.com'):
                if parsed_url.path.endswith('/'):
                    return render_template('result.html', result='True')
                else:
                    return render_template('result.html', result='False')
            else:
                return render_template('result.html', result='False')

        except Exception as e:
            print(f"Error parsing URL: {e}")
            return render_template('result.html', result='False')

    return render_template('check_url.html', form=form)


def is_valid_url(url):
    if not url:
        return False
    allowed_chars = r"^[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*$"
    if not re.match(allowed_chars, url):
        return False
    if len(url) > 2048:
        return False
    return True

@app.after_request
def after_request(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Changed to HTML
    return response

if __name__ == '__main__':
    app.run(debug=False)

