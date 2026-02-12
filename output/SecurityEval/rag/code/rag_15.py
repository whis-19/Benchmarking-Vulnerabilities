from flask import Flask, request, make_response, render_template, escape

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

@app.route('/view', methods =['GET'])
def viewName():
    '''
    Get the param "name" from the request.
    Open the "templates/xss_shared.html" file and replace  "{{name}}" with the "name" param.
    return the html file as a response.
    '''
    name = request.args.get('name', '')

    # Sanitize the input using escape to prevent XSS
    safe_name = escape(name)

    # Render the template with the sanitized name
    html = render_template('xss_shared.html', name=safe_name)

    response = make_response(html)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding

    # Set HttpOnly flag for session cookie (if you're using sessions)
    # Example:
    # response.set_cookie('session', 'your_session_id', httponly=True)

    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

