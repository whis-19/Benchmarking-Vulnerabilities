from flask import request, session

    @app.route('/submit', methods=['POST'])
    def submit():
        if request.method == 'POST':
            csrf_token = request.form.get('csrf_token')
            if csrf_token != session.get('csrf_token'):
                return Response("CSRF token invalid", status=400)
            # Process the form data here
            return "Form submitted successfully!"

