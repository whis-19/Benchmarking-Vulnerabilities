from flask import Flask, render_template, session, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))
csrf = CSRFProtect(app)

class MessageForm(FlaskForm):
    message = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Post')

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    form = MessageForm()
    if form.validate_on_submit():
        message = form.message.data
        # ... your message posting logic ...
        return redirect(url_for('index'))
    messages = get_messages()
    return render_template('index.html', messages=messages, form=form)

# In your index.html template:
# <form method="POST">
#   {{ form.csrf_token }}
#   {{ form.message.label }} {{ form.message() }}
#   {{ form.submit() }}
# </form>

