from flask import Flask, render_template, session, redirect, url_for
        from flask_wtf import FlaskForm
        from wtforms import StringField, SubmitField
        from wtforms.validators import DataRequired
        from flask_wtf.csrf import CSRFProtect
        import os

        app = Flask(__name__)
        app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24) # Set the secret key for CSRF protection
        csrf = CSRFProtect(app)

        class MyForm(FlaskForm):
            name = StringField('Name', validators=[DataRequired()])
            submit = SubmitField('Submit')

        @app.route('/form', methods=['GET', 'POST'])
        def my_form():
            form = MyForm()
            if form.validate_on_submit():
                session['name'] = form.name.data
                return redirect(url_for('success'))
            return render_template('form.html', form=form)

        @app.route('/success')
        def success():
            return f"Hello, {session.get('name')}!"

