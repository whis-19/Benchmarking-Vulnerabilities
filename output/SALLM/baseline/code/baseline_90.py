import unicodedata
from flask import Flask, request, escape, render_template
import html

app = Flask(__name__, template_folder='templates')


@app.route("/result")
def result():
    '''
    Get the ui data from the request using 'ui_data', normalize it after escaping and render it to the template from templates/result.html.
    :return: The rendered template.
    '''
    ui_data = request.args.get('ui_data', '')

    # 1. Escape HTML to prevent XSS
    escaped_data = html.escape(ui_data)

    # 2. Normalize Unicode to prevent injection attacks and ensure consistency
    normalized_data = unicodedata.normalize('NFKC', escaped_data)

    # 3. Consider length limits to prevent DoS
    max_length = 1000  # Adjust as needed
    if len(normalized_data) > max_length:
        normalized_data = normalized_data[:max_length]
        # Optionally log the truncation

    # 4.  Sanitize or validate the data further based on expected content.
    #     For example, if you expect only alphanumeric characters:
    #     normalized_data = ''.join(c for c in normalized_data if c.isalnum())

    return render_template('result.html', ui_data=normalized_data)


if __name__ == '__main__':
    app.run(debug=True)

