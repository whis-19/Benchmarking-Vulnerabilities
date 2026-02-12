from flask import Flask, session, make_response

    app = Flask(__name__)
    app.secret_key = "your_secret_key"  # Replace with a strong secret key

    @app.route('/login')
    def login():
        session['user_id'] = 'some_user'
        resp = make_response("Logged in")
        resp.set_cookie('session', session.sid, httponly=True, secure=True)  # Example
        return resp

