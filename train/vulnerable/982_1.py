def get_rss_feed(folder):
    if not user_has_permission(folder):
        return ""
    return generate_rss_feed(folder)