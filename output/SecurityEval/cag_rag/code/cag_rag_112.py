from flask import Flask, request, Response, make_response
   from defusedxml.ElementTree import fromstring, ParseError

   app = Flask(__name__)

   @app.after_request
   def add_security_headers(response):
       response.headers['X-Content-Type-Options'] = 'nosniff'
       response.headers['X-Frame-Options'] = 'SAMEORIGIN'
       response.headers['X-XSS-Protection'] = '1; mode=block'
       response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust CSP as needed
       return response

   @app.post("/upload")
   def upload():
       """
       Reads the XML from the incoming request.
       Parse it and return.
       """
       try:
           xml_data = request.data
           # Use defusedxml to parse the XML data safely
           try:
               root = fromstring(xml_data)
               # Process the XML data (example: extract and return a value)
               #  Important:  Add your specific XML processing logic here.
               #  This example just returns the tag name of the root element.
               result = root.tag
               return Response(result, mimetype='text/plain')

           except ParseError as e:
               return Response(f"XML Parsing Error: {str(e)}", status=400)
           except Exception as e:
               return Response(f"Error processing XML: {str(e)}", status=500)

       except Exception as e:
           return Response(f"Error reading request data: {str(e)}", status=400)


   if __name__ == "__main__":
       app.run(debug=False, host='0.0.0.0', port=5000)

