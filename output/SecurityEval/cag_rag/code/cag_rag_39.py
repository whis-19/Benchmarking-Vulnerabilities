from flask import Flask, request

app = Flask(__name__)

@app.route('/get_record')
def get_record_route():
    result = getRecord(request)
    if isinstance(result, tuple):  # Check for error response (message, status code)
        return result[0], result[1]
    else:
        return str(result)

if __name__ == '__main__':
    app.run(debug=True)

