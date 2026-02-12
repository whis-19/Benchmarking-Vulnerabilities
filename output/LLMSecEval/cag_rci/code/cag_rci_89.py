from flask import Flask, render_template, request, jsonify, make_response
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length
import bleach
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong secret key.  For production, store this in an environment variable or configuration file for persistence.
csrf = CSRFProtect(app)

class MyForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=255)])
    submit = SubmitField('Submit')

    def validate_name(form, field):
        allowed_tags = ['p', 'a', 'strong', 'em']  # Example: Allow only these tags.  Review carefully to minimize XSS risk.
        allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt']} # Example: Allow only these attributes. Review carefully to minimize XSS risk.
        field.data = bleach.clean(field.data, tags=allowed_tags, attributes=allowed_attributes)
        # Alternatively, focus on escaping in the template.

@app.route('/', methods=['GET', 'POST'])
def index():
    form = MyForm()
    if form.validate_on_submit():
        name = form.name.data
        return render_template('result.html', name=name)
    return render_template('index.html', form=form)

@app.route('/csp_report', methods=['POST'])
def csp_report():
    # Process the CSP report (e.g., log it, send an email)
    report = request.get_json()
    logging.info("CSP Report: %s", report)  # Use logging instead of print
    return '', 204  # Return a 204 No Content response

@app.route('/api/process', methods=['POST'])
def process_api():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        if 'name' in data:
            name = data['name']
            # Validate the name (example: length)
            if len(name) > 100:
                return jsonify({"error": "Name too long"}), 400

            # Security: Escape user input before returning in JSON (using jsonify)
            return jsonify({"name": name})
        else:
            return jsonify({"error": "Missing 'name' field"}), 400

    except (ValueError, TypeError, KeyError) as e:  # Catch specific exceptions
        logging.error(f"Error processing API request: {e}") # Log the error (important for debugging)
        return jsonify({"error": "Invalid data format"}), 400  # More specific error message
    except Exception as e:
        logging.exception("Unexpected error processing API request") # Log the full exception
        return jsonify({"error": "Internal server error"}), 500

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # Enforce HTTPS
    response.headers['X-Frame-Options'] = 'DENY'  # Prevent clickjacking
    response.headers['Content-Type'] = 'application/json' # Ensure correct content type
    return response

if __name__ == '__main__':
    app.run(debug=True)

