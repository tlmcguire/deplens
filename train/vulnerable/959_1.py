def create_paste(request):
    if request.method == 'POST':
        expires = request.POST.get('expires', '')

        paste = Paste.objects.create(content=request.POST['content'], expires=expires)
        return redirect('paste_detail', paste_id=paste.id)