import logging

    logging.basicConfig(filename='myapp.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    @app.route('/some_route')
    def some_route():
        try:
            # ... some code that might raise an exception
        except Exception as e:
            logging.exception("An error occurred: %s", e)
            flash("An error occurred. Please try again later.", "error")
            return redirect(url_for('index'))

