from flask import Flask, render_template, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
import logging
import re
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')  # Use a strong, random key in production
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MyForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = MyForm()
    if form.validate_on_submit():
        name = form.name.data
        # Sanitize input (example: remove HTML tags)
        name = re.sub(r'<[^>]*>', '', name)  # Remove HTML tags
        logging.info(f"Received name: {name}")
        return render_template('success.html', name=name)
    return render_template('index.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)

