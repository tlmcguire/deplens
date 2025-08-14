from flask import escape, render_template

@app.route('/your_endpoint')
def your_view_function():
    data = get_data_from_database()

    safe_data = escape(data['endpoint'])

    return render_template('your_template.html', endpoint=safe_data)