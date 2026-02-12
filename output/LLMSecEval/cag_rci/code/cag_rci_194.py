from flask import session

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            # Input validation
            if not (username and password):
                flash('Username and password are required.', 'danger')
                return render_template('login.html')

            # Find user
            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                session.clear()  # Regenerate session - clear existing session
                session['user_id'] = user.id  # Repopulate with user ID
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
                # Increment failed login attempts counter in session
                session['failed_login_attempts'] = session.get('failed_login_attempts', 0) + 1
                return render_template('login.html')
        else:
            # Reset failed login attempts on GET request
            session.pop('failed_login_attempts', None)
            return render_template('login.html')

    # Modify the rate limiter to use the session-based counter
    def login_rate_limit(limit="5 per minute"):
        def decorator(f):
            @wraps(f)
            @limiter.limit(limit, key_func=lambda: get_remote_address() + str(session.get('failed_login_attempts', 0)))
            def decorated_function(*args, **kwargs):
                return f(*args, **kwargs)
            return decorated_function
        return decorator

