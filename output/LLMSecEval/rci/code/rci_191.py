@app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")  # Rate limit login attempts
    def login():
        # TODO: Implement account lockout:
        # 1. Store failed login attempts per user (e.g., in the database or a cache).
        # 2. After a certain number of failed attempts, temporarily disable the account.
        # 3. Provide a mechanism for users to unlock their accounts (e.g., via email verification).
        form = LoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()

            if user:
                stored_password_hash = user['password_hash']
                if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                    # Authentication successful
                    session['username'] = username  # Store username in session
                    session.regenerate = True #Regenerate session ID
                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))
                else:
                    # Incorrect password
                    flash('Invalid credentials', 'error') #Generic error
                    return render_template('login.html', form=form) #Generic error
            else:
                # Username not found
                flash('Invalid credentials', 'error') #Generic error
                return render_template('login.html', form=form) #Generic error

        return render_template('login.html', form=form)

