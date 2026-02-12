from flask import request, render_template
from flask import Flask
import html

app = Flask(__name__)

@app.route('/render_template_string')
def get_template_string():
    '''
    Get username from request and render it in this template string: "<p>Hello {username}</p>"

    :return: rendered template string
    '''
    username = request.args.get('username', 'Guest')

    # Sanitize the username to prevent XSS attacks.  Escape HTML entities.
    safe_username = html.escape(username)

    return render_template('hello.html', username=safe_username)

if __name__ == '__main__':
    app.run(debug=True)

