from django.shortcuts import render

def my_view(request):
    # ... your view logic ...
    response = set_location_header(request)
    return response

