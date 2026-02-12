import re

   @app.route('/parse_xml')
   def parse_xml():
       xml_src = request.args.get('xml_src')

       if not xml_src:
           return "Error: xml_src parameter is missing", 400

       # Basic character set validation (allow alphanumeric, spaces, and common XML characters)
       if not re.match(r"^[a-zA-Z0-9\s<>/\"'=]+$", xml_src):
           return "Error: Invalid characters in XML data", 400

       try:
           xml_doc = fromstring(xml_src)
           xml_string = tostring(xml_doc, encoding='utf8').decode('utf8')
           return xml_string, 200

       except lxml.etree.XMLSyntaxError as e:
           return f"Error: Invalid XML syntax: {e}", 400
       except Exception as e:
           return f"Error: An unexpected error occurred: {e}", 500

