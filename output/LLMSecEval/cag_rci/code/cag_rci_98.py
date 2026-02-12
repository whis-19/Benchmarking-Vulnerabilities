from your_models import User, db  # Import your database models
from wtforms import ValidationError

def username_exists(form, field):
    """
    Validator to check if a username already exists in the database.
    """
    username = field.data.strip()  # Remove leading/trailing whitespace

    # Input Validation:  Enforce length and character set restrictions
    if not (4 <= len(username) <= 25 and username.isalnum()):  # Example validation
        raise ValidationError("Username must be between 4 and 25 alphanumeric characters.")

    user = User.query.filter_by(username=username).first()
    if user:
        raise ValidationError('Username already exists.')

