def get_rss_feed(folder, user):
    if not user.has_permission('View', folder):
        raise PermissionError("User  does not have permission to access this folder.")

    rss_feed = generate_rss_feed(folder)
    return rss_feed