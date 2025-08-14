from flask import Flask, request

app = Flask(__name__)

def render_wiki_content(wiki_code):
    exec(wiki_code)

@app.route('/execute', methods=['GET'])
def execute_code():
    user_input = request.args.get('code')
    if user_has_view_access():
        render_wiki_content(user_input)
        return "Code executed!"
    else:
        return "Access denied!", 403

def user_has_view_access():
    return True

if __name__ == '__main__':
    app.run(debug=True)