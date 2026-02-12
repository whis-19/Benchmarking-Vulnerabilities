from wtforms.validators import Regexp

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=50),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers, and underscores")
    ])
    password = StringField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

