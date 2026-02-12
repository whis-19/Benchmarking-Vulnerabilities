from flask_wtf import FlaskForm
    from wtforms import StringField, FileField
    from wtforms.validators import DataRequired
    from flask_wtf.csrf import CSRFProtect

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong, random key
    csrf = CSRFProtect(app)

    class UploadForm(FlaskForm):
        username = StringField('Username', validators=[DataRequired()])
        file = FileField('File', validators=[DataRequired()])

    @app.route('/upload', methods=['POST', 'GET'])
    def upload():
        form = UploadForm()
        if form.validate_on_submit():
            # ... your upload logic here, using form.username.data and form.file.data ...
            return "File uploaded successfully", 200
        return render_template('upload.html', form=form)

