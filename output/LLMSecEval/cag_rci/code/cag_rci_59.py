# Login Example (Illustrating check_password_hash)
from werkzeug.security import check_password_hash

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ... (Get username and password from form)
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        # Login successful (set session)
        session['user_id'] = user.id  # Example: Store user ID in session
        return redirect(url_for('home')) # Redirect to home page
    else:
        # Login failed
        flash('Login unsuccessful. Please check your username and password.', 'danger')
        return render_template('login.html', form=form)

