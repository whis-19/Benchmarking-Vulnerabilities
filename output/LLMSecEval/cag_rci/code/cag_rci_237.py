if user is None or not user.check_password(password):
            flash('Invalid username or password.', 'danger')
            return render_template('login.html', form=form)

