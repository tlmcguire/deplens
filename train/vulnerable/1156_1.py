from nicegui import ui

@ui.route('/_nicegui/{__version__}/resources/{key}/{path:path}')
def serve_resource(key, path):
    return ui.send_file(f'resources/{key}/{path}')

ui.run()