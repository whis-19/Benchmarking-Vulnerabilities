from django.shortcuts import render

def my_view(request):
    if request.method == 'POST':
        # Process form data
        return http_responser_redirect(request)  # Redirect after processing

    return render(request, 'my_template.html')

