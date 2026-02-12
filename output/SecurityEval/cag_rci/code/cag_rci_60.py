from flask_wtf import FlaskForm
        from wtforms import StringField, SubmitField
        from wtforms.validators import DataRequired

        class MyForm(FlaskForm):
            name = StringField('Name', validators=[DataRequired()])
            submit = SubmitField('Submit')

        @app.route('/my_route', methods=['GET', 'POST'])
        def my_route():
            form = MyForm()
            if form.validate_on_submit():
                # Process the form data
                return 'Success!'
            return render_template('my_template.html', form=form)

