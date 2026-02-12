# --- Configuration ---
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# --- Routes ---
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)]) # Add more complex validators
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # ... your registration logic ...
        return redirect(url_for('login')) # Redirect to login page
    return render_template('register.html', form=form) # Render the form

# Similar form for login

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Invalid credentials'}), 400 # Generic message

    if is_rate_limited(username):
        return jsonify({'message': 'Too many login attempts. Please try again later.'}), 429

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        update_login_attempts(username, success=True)
        session['user_id'] = user.id  # Store user ID in session
        session.regenerate() # Regenerate session ID
        return jsonify({'message': 'Login successful'}), 200
    else:
        update_login_attempts(username)
        return jsonify({'message': 'Invalid credentials'}), 401 # Generic message

