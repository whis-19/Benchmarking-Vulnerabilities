from flask import Response, request, Flask, make_response
import html

app = Flask(__name__)

@app.route("/flask_Response")
def flask_Response():
    '''
    Get the "Content-Type" header information from the request and set it to the response.
    :return: The response with the "Content-Type" header.
    '''
    content_type = request.headers.get("Content-Type")

    # Sanitize the content_type to prevent header injection.
    #  - Limit the length to prevent excessively long headers.
    #  - Only allow alphanumeric characters, slashes, hyphens, and semicolons.
    #  - Escape any HTML entities to prevent XSS.
    if content_type:
        sanitized_content_type = ''.join(c for c in content_type[:256] if c.isalnum() or c in '/;-')
        sanitized_content_type = html.escape(sanitized_content_type)

        response = make_response("Content-Type set based on request.")
        response.headers["Content-Type"] = sanitized_content_type
        return response
    else:
        return "Content-Type header not found in request.", 400


if __name__ == '__main__':
    app.run(debug=False)

