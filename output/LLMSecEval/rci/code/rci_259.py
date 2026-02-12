from bleach import clean

    @app.route('/some_route', methods=['POST'])
    def some_route():
        user_input = request.form.get('user_input')
        cleaned_input = clean(user_input)  # Sanitize the input
        # ... use cleaned_input in your application

