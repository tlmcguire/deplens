def filter_view(request):
    user_input = request.GET.get('filter_param', '')
    response = f"<div>User input: {user_input}</div>"
    return HttpResponse(response)