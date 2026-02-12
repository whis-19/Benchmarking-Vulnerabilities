from flask_wtf import FlaskForm
    from wtforms import StringField, SubmitField
    from wtforms.validators import DataRequired, Length

    class MyForm(FlaskForm):
        name = StringField('Name', validators=[DataRequired(), Length(max=20)])
        submit = SubmitField('Submit')

    @app.route('/myroute', methods=['GET', 'POST'])
    def my_route():
        form = MyForm()
        if form.validate_on_submit():
            # Process the form data
            name = form.name.data
            return f"Hello, {name}!"
        return render_template('my_template.html', form=form)

