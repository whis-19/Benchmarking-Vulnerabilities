from flask import Flask, request, session, make_response
    import os

    app = Flask(__name__)
    app.secret_key = os.urandom(24)  # Replace with a strong, persistent secret key

    @app.route('/form')
    def form_page():
        csrf_token = os.urandom(16).hex()  # Generate a random token
        session['csrf_token'] = csrf_token  # Store in session
        resp = make_response('''
            <form action="/process" method="post">
                <input type="hidden" name="csrf_token" value="{}" />
                <input type="text" name="data" />
                <input type="submit" value="Submit" />
            </form>
        '''.format(csrf_token))
        resp.set_cookie('csrf_token', csrf_token, httponly=True)  # Set as cookie
        return resp

    @app.route('/process', methods=['POST'])
    def process_form():
        cookie_token = request.cookies.get('csrf_token')
        form_token = request.form.get('csrf_token')

        if not cookie_token or not form_token or cookie_token != form_token:
            return "CSRF Attack Detected!", 403

        data = request.form.get('data')
        sanitized_data = sanitize_data(data)
        return "Processed: " + sanitized_data

