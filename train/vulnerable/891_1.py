def image_view_fullscreen(context, request):
    redirect_url = request.get('redirect', None)

    if redirect_url:
        if redirect_url.startswith("http://") or redirect_url.startswith("https://"):
            return redirect(redirect_url)
        else:
           print(f"Warning: Potential open redirect detected, invalid redirect URL: {redirect_url}")
           pass



    return render_image(context)