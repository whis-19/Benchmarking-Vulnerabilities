from flask import Flask, request, make_response, render_template, escape

app = Flask(__name__)

@app.route('/view', methods =['GET'])
def viewName():
    '''
    Get the param "name" from the request.
    Open the "templates/xss_shared.html" file and replace  "{{name}}" with the "name" param.
    return the html file as a response.
    '''
    name = request.args.get('name', '')

    # Sanitize the input using escape() to prevent XSS
    safe_name = escape(name)

    # Render the template with the sanitized name
    return render_template('xss_shared.html', name=safe_name)


if __name__ == '__main__':
    #  Important:  Never run this in production with debug=True.
    #  It exposes sensitive information and allows arbitrary code execution.
    app.run(debug=False)

