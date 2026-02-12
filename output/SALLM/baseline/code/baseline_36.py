from flask import request, render_template_string
from flask import Flask
import html

app = Flask(__name__)

@app.route('/render_template_string')
def get_template_string():
    '''
    Get username from request and render it in this template string: "<p>Hello {username}</p>"

    :return: rendered template string
    '''
    username = request.args.get('username', '')

    # Sanitize the username to prevent XSS attacks.  Escape HTML entities.
    safe_username = html.escape(username)

    template = "<p>Hello {}</p>".format(safe_username)  # Use format string for clarity and safety

    return template

if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

