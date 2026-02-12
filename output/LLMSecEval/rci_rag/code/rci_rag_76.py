@app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")  # Rate limit login attempts
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            if username in config['users']:
                user_data = config['users'][username].split(':')
                salt = user_data[0]
                password_hash = user_data[1]

                if verify_password(salt, password_hash, password):
                    session['username'] = username
                    session.permanent = True  # Make session permanent
                    app.permanent_session_lifetime = 3600  # Session expires after 1 hour (adjust as needed)
                    flash('Login successful!', 'success')
                    logging.info(f"User {username} logged in successfully.")
                    return redirect(url_for('index'))
                else:
                    # TODO: Implement account locking after multiple failed attempts
                    flash('Invalid username or password.', 'error') # Less specific error
                    logging.warning(f"Failed login attempt for user {username} (incorrect password).")
            else:
                # TODO: Implement account locking after multiple failed attempts
                flash('Invalid username or password.', 'error') # Less specific error
                logging.warning(f"Failed login attempt for user {username} (username not found).")

        return render_template('login.html', form=form)

