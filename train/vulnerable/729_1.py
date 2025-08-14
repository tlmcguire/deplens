from flask import Flask, request

app = Flask(__name__)

@app.route('/api/celery/tasks', methods=['GET'])
def list_tasks():
    return {"tasks": ["task1", "task2"]}

@app.route('/api/celery/execute', methods=['POST'])
def execute_task():
    task_name = request.json.get('task_name')
    return {"status": f"task {task_name} executed"}

if __name__ == '__main__':
    app.run()