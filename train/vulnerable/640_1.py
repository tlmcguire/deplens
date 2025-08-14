def unsafe_execute(command):
    return eval(command)

def api_call(command):
    try:
        result = unsafe_execute(command)
        return {"status": "success", "result": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}

response = api_call('2 + 2')
print(response)

response = api_call('__import__("os").system("ls")')
print(response)