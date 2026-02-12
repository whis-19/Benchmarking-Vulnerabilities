import requests

   xml_data = "<root><element>Some data</element></root>"
   data = {'xml_src': xml_data}
   response = requests.post('http://localhost:5000/xml_upload', data=data)

   if response.status_code == 200:
       print(response.content.decode('utf-8'))
   else:
       print(f"Error: {response.status_code} - {response.text}")

