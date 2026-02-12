from flask_wtf import FlaskForm
    from wtforms import StringField, PasswordField, SubmitField
    from wtforms.validators import DataRequired

    app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY') or secrets.token_hex(16)

    class LoginForm(FlaskForm):
        username = StringField('Username', validators=[DataRequired()])
        password = PasswordField('Password', validators=[DataRequired()])
        submit = SubmitField('Login')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            user = users.get(username)
            if user and check_password_hash(user['password'], password):
                user_obj = User(username, user['role'])
                login_user(user_obj)
                return redirect(url_for('deleteImage'))
            else:
                return 'Invalid username or password'
        return render_template('login.html', form=form) # You'll need to create a login.html template

