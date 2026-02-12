from flask import Flask, make_response

app = Flask(__name__)

@app.route('/')
def index():
    resp = make_response("Hello, world!")
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Content-Security-Policy'] = "default-src 'self'"
    return resp

