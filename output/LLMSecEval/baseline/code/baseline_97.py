from flask import session

   # ... inside the login route after successful login ...
   session['username'] = username  # Store the username in the session
   return redirect(url_for('profile')) # Redirect to a user profile page

   @app.route('/profile')
   def profile():
       if 'username' in session:
           return f"Welcome, {session['username']}!"
       else:
           return redirect(url_for('login'))

   @app.route('/logout')
   def logout():
       session.pop('username', None)  # Remove the username from the session
       return redirect(url_for('index'))

