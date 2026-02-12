# ... (Existing code) ...

# Input Validation
def validate_email_format(form, field):
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_regex, field.data):
        raise ValidationError("Invalid email format.")


# Forms
class UnsubscribeForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(), Email(), validate_email_format])
    submit = SubmitField('Unsubscribe')

    def validate_email(self, field):
        field.data = field.data.strip()  # Sanitize email
        validate_email_format(self, field) # Keep existing validation

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired(),
                                     Length(min=8),
                                     Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                                            message="Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")])
    submit = SubmitField('Register')

    def validate_username(self, field):
        field.data = field.data.strip()  # Sanitize username

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# ... (Existing code) ...

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    csp_nonce = secrets.token_urlsafe(16)
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = get_user(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session.regenerate() # Add this line (assuming you're using Flask-Session)
            flash('Login successful!', 'success')
            return redirect(url_for('protected'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form, csp_nonce=csp_nonce)

# ... (Existing code) ...

@app.after_request
def add_csp_header(response):
    nonce = secrets.token_urlsafe(16)
    csp = f"""
    default-src 'self';
    script-src 'self' 'nonce-{nonce}';
    style-src 'self'; /* Removed unsafe-inline!  Move styles to external files or use nonces */
    img-src 'self' data:;
    font-src 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    block-all-mixed-content;
    upgrade-insecure-requests;
    report-uri /csp_report; /* Add this line */
    """
    response.headers['Content-Security-Policy'] = csp.replace('\n', ' ')
    return response

@app.route('/csp_report', methods=['POST'])
def csp_report():
    # Handle CSP reports here.  Log them, analyze them, etc.
    logger.warning("CSP Violation: %s", request.get_data(as_text=True))
    return '', 204  # Return a 204 No Content response

