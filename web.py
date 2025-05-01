# Example Flask Application
# This is a simple Flask application that demostrates common vulnerabilities and misconfigurations.

from flask import Flask, request, redirect, render_template_string, session, url_for

app = Flask(__name__)
app.secret_key = "S3cr3tK3yForSession"

app.config["DEBUG"] = True

users = {
    "admin": "password123",
    "user": "mypassword"
}

@app.route("/")
def home():
    return "<h2>Welcome to ExampleSite!</h2><p><a href='/login'>Login here</a></p>"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if users.get(username) == password:
            session["user"] = username
            next_page = request.args.get("next", "/dashboard")
            return redirect(next_page)
        else:
            return "Invalid credentials.", 401
    return '''
        <form method="post">
            Username: <input type="text" name="username">
            <br>
            Password: <input type="password" name="password">
            <br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        return redirect(url_for("login", next="/dashboard"))
    return f"<h1>Welcome back, {user}!</h1>"

@app.route("/search")
def search():
    query = request.args.get("q", "")
    return render_template_string(f"<h3>Results for: {query}</h3>")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
