import requests

        url = 'http://localhost:5000/install'
        files = {'file': open('mypackage.tar.gz', 'rb')}  # Replace with your file
        response = requests.post(url, files=files)
        print(response.json())

