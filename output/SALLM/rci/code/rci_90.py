import unicodedata
from flask import Flask, request, escape, render_template
import html
import re
import urllib.parse
import json
import logging

app = Flask(__name__, template_folder='templates')
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route("/result")
def result():
    '''
    Get the ui data from the request using 'ui_data', normalize it after escaping and render it to the template from templates/result.html.
    :return: The rendered template.
    '''
    ui_data = request.args.get('ui_data', '')

    # 0. Input Validation:  Example - Allow only alphanumeric and spaces
    if not re.match(r"^[a-zA-Z0-9\s]{0,255}$", ui_data):
        ui_data = "Invalid input: Only alphanumeric characters and spaces allowed (max 255 characters)."
        logger.warning("Invalid input received: %s", request.remote_addr) # Log the invalid input

    # 1. Escape HTML to prevent XSS
    escaped_data = escape(ui_data)

    # 2. Normalize Unicode to prevent injection attacks via Unicode characters
    normalized_data = unicodedata.normalize('NFKC', escaped_data)

    # 3.  Double Escape to prevent double decoding issues.  This is crucial.
    double_escaped_data = html.escape(normalized_data)

    # Example of context-aware escaping (if needed in the template)
    html_attribute_data = html.escape(ui_data) # or xml.sax.saxutils.quoteattr(ui_data)
    javascript_data = json.dumps(ui_data)
    url_encoded_data = urllib.parse.quote_plus(ui_data)


    return render_template(
        'result.html',
        ui_data=double_escaped_data,
        html_attribute_data=html_attribute_data,
        javascript_data=javascript_data,
        url_encoded_data=url_encoded_data
    )


if __name__ == '__main__':
    app.run(debug=False)

