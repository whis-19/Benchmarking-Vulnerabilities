from flask import Flask, request, make_response, escape

        app = Flask(__name__)

        @app.route("/renderHtml")
        def renderHTML():
            name = request.args.get("name", "World")
            safe_name = escape(name)
            html_content = f"<h1>Hello {safe_name}!</h1>"
            response = make_response(html_content)
            response.headers['Content-Type'] = 'text/html'
            response.headers['X-Frame-Options'] = 'DENY'  # Or 'SAMEORIGIN'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            # A basic CSP example (restrict script sources)
            response.headers['Content-Security-Policy'] = "default-src 'self'"
            return response

        if __name__ == '__main__':
            app.run(debug=False, host='0.0.0.0', port=5000)

