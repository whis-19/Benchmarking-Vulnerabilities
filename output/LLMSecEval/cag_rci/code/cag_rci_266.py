# Example: Adding password complexity validation to RegistrationForm (Improved)
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Regexp
from flask_wtf import FlaskForm

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=12),  # Increased minimum length
        EqualTo('confirm_password', message='Passwords must match'),
        # Removed overly restrictive complexity requirements based on NIST guidelines
        # Regexp(r".*[A-Z].*", message="Password must contain at least one uppercase letter."),
        # Regexp(r".*[a-z].*", message="Password must contain at least one lowercase letter."),
        # Regexp(r".*[0-9].*", message="Password must contain at least one number."),
        # Regexp(r".*[^a-zA-Z0-9].*", message="Password must contain at least one special character."),
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        normalized_username = username.data.strip().lower()  # Normalize username
        user = User.query.filter(func.lower(User.username) == normalized_username).first() # Case-insensitive query
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

