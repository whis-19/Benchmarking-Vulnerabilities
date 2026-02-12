from flask_wtf import FlaskForm
   from wtforms import StringField, PasswordField, SubmitField
   from wtforms.validators import DataRequired

   class LoginForm(FlaskForm):
       username = StringField('Username', validators=[DataRequired()])
       password = PasswordField('Password', validators=[DataRequired()])
       submit = SubmitField('Login')

   # ... in your route
   form = LoginForm()
   if form.validate_on_submit():
       # ... process the form data
   return render_template('login.html', form=form)

