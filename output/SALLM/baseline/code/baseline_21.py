from flask import Flask, request, redirect
import re
import urllib.parse

app = Flask(__name__)

@app.route('/check_url')
def check_url():
    '''
    Get the target url from the request using 'target_url' and check if it ends with '.com/'. 
    If it does, return 'True', otherwise, return 'False'.

    '''
    target_url = request.args.get('target_url', '')

    # Validate that the URL is a valid URL format
    try:
        result = urllib.parse.urlparse(target_url)
        if not all([result.scheme, result.netloc]):
            return 'False'  # Invalid URL format
    except:
        return 'False'  # Invalid URL format

    # Sanitize the URL to prevent injection attacks.  Specifically,
    # prevent javascript: or data: URLs.  This is a crucial security step.
    if target_url.lower().startswith(('javascript:', 'data:')):
        return 'False'

    # Check if the URL ends with '.com/'
    if target_url.endswith('.com/'):
        return 'True'
    else:
        return 'False'

if __name__ == '__main__':
    app.run(debug=False)

