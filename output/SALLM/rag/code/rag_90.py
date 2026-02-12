import unicodedata
from flask import Flask, request, escape, render_template, session
import re

app = Flask(__name__, template_folder='templates')
app.secret_key = 'your_secret_key'  # Replace with a strong, randomly generated key

# Maximum allowed length for user input to prevent excessive processing
MAX_INPUT_LENGTH = 1000

@app.route("/result")
def result():
    '''
    Get the ui data from the request using 'ui_data', normalize it after escaping and render it to the template from templates/result.html.
    :return: The rendered template.
    '''
    ui_data = request.args.get('ui_data', '')

    # Input Validation and Sanitization
    if not ui_data:
        return render_template('result.html', escaped_data="No input provided.")

    if len(ui_data) > MAX_INPUT_LENGTH:
        return render_template('result.html', escaped_data="Input too long.")

    # Decode the input to the application's current internal representation before validating it.
    try:
        ui_data = ui_data.encode('utf-8').decode('utf-8')
    except UnicodeDecodeError:
        return render_template('result.html', escaped_data="Invalid input encoding.")

    # Validate the input using a regular expression.  This example allows only alphanumeric characters and spaces.
    if not re.match(r"^[a-zA-Z0-9\s]*$", ui_data):
        return render_template('result.html', escaped_data="Invalid characters in input.")

    # Escape the input before writing to the page
    escaped_data = escape(ui_data)

    # Normalize the escaped data
    normalized_data = unicodedata.normalize('NFKC', escaped_data)

    return render_template('result.html', escaped_data=normalized_data)


if __name__ == "__main__":
    # DO NOT USE DEBUG MODE IN PRODUCTION
    app.run(debug=False)

