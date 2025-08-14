import uvicorn
import urllib.parse

def sanitize_input(scope):
    safe_scope = {}
    for key, value in scope.items():
        if isinstance(value, str):
            safe_scope[key] = urllib.parse.quote(value)
        else:
            safe_scope[key] = value
    return safe_scope

async def app(scope, receive, send):
    safe_scope = sanitize_input(scope)
    print(safe_scope)

    assert scope['type'] == 'http'
    await send({
        'type': 'http.response.start',
        'status': 200,
        'headers': [
            [b'Content-Type', b'text/plain']
        ]
    })
    await send({
        'type': 'http.response.body',
        'body': b'Hello, world!',
    })

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)