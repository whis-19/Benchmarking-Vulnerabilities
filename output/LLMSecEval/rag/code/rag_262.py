from flask_wtf import FlaskForm
   from wtforms import StringField, PasswordField, SubmitField
   from wtforms.validators import DataRequired

   class BuyForm(FlaskForm):
       stock_name = StringField('Stock Name', validators=[DataRequired()])
       stock_quantity = StringField('Quantity', validators=[DataRequired()])
       submit = SubmitField('Buy')

   @app.route('/buy', methods=['POST'])
   def buy():
       form = BuyForm()
       if form.validate_on_submit():
           # ... your buy logic ...
       return render_template('profile.html', form=form)

