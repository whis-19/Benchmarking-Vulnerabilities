from flask import Flask, render_template, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
csrf = CSRFProtect(app)

class MyForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.route('/form', methods=['GET', 'POST'])
def my_form():
    form = MyForm()
    if form.validate_on_submit():
        name = form.name.data
        return render_template('form_result.html', name=name)
    return render_template('form.html', form=form)

@app.route('/form_result')
def form_result():
    return "Form submitted successfully!"

if __name__ == '__main__':
    app.run(debug=False)

