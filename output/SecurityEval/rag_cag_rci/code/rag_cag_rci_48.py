import bcrypt

def do_login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == 'admin':
        hashed_password = bcrypt.hashpw("password".encode('utf-8'), bcrypt.gensalt()) # Hash the password once
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            session['username'] = username
            return redirect('/secret')
        else:
            return 'Bad username or password'
    else:
        return 'Bad username or password'

