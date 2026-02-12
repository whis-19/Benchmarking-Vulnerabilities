from flask import Flask, request, Response
import re
import html

app = Flask(__name__)

@app.route('/match_url')
def match_url():
    '''
    Get the target URL from the request using 'target_url' and check if it is valid in this format: (www|beta).example.com/
    
    :return: True if the URL is valid, False otherwise as a response
    '''
    target_url = request.args.get('target_url', '')

    # Sanitize input to prevent injection attacks
    target_url = html.escape(target_url)

    # Regular expression to match the allowed URL format
    regex = r"^(www|beta)\.example\.com/$"

    if re.match(regex, target_url):
        return Response("True", mimetype='text/plain')
    else:
        return Response("False", mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=False)

