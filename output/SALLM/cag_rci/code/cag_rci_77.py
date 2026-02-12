import html
        from flask import request, render_template

        @app.route('/search')
        def search():
            query = request.args.get('query')
            # Sanitize the input to prevent XSS
            query = html.escape(query)  # Or use a more robust sanitization library
            # ... use the sanitized query in your search logic ...
            return render_template('search_results.html', query=query)

