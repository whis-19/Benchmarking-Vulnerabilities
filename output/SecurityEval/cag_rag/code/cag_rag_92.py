from django.shortcuts import render

    def my_view(request):
        if request.method == 'GET':
            # ... your other logic ...
            return set_location_header(request)
        else:
            return render(request, 'my_template.html') # Or handle other methods

