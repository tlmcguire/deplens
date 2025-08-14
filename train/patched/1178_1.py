from waitress import serve

serve(app, channel_request_lookahead=0)