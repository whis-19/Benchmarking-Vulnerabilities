from flask import Flask, request, make_response, escape

app = Flask(__name__)

@app.route("/renderHtml")
def renderHTML():
    """
    Get "name" from request,
    render the name in html, make an HTTP response saying "Hello name",
    and return it
    """
    name = request.args.get("name", "World")  # Default to "World" if name is not provided

    # Sanitize the input to prevent XSS attacks.  Use escape() from flask.
    safe_name = escape(name)

    html_content = f"<h1>Hello {safe_name}!</h1>"  # Use f-strings for cleaner formatting

    response = make_response(html_content)
    response.headers['Content-Type'] = 'text/html'  # Explicitly set content type

    return response

if __name__ == '__main__':
    #  Never run in production with debug=True.  It exposes sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

