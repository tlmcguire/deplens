from nicegui import ui

@ui.route('/safe_resources/<path:key>/<path:path>')
def safe_resources(key, path):
    if is_valid_key(key) and is_valid_path(path):
        return serve_resource(key, path)
    else:
        return ui.response('Forbidden', status=403)

def is_valid_key(key):
    return key in allowed_keys

def is_valid_path(path):
    return not any(part in path for part in ['..', '/'])

def serve_resource(key, path):
    return ui.send_file(f'resources/{key}/{path}')

ui.run()