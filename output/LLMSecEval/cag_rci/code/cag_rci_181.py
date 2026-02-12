@app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            # csrf_token = request.form.get('csrf_token') # Assuming you have CSRF protection

            # if not validate_csrf_token(csrf_token):
            #     abort(400, "CSRF token validation failed.")

            ip_address = request.remote_addr

            if is_rate_limited(ip_address):
                return "Too many login attempts. Please try again later.", 429

            if verify_password(username, password):
                session['username'] = username
                session.regenerate()
                return redirect(url_for('protected'))
            else:
                increment_login_attempts(ip_address)
                return "Invalid credentials", 401  # Generic error message

        return render_template('login.html') #, csrf_token=session['csrf_token'])

