# GOOD - Safe from SQL injection
    username = request.form['username']
    user = User.query.filter_by(username=username).first()

