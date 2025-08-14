@app.route('/users', methods=['GET'])
@admin_required
def get_users_fixed():
    users = User.query.all()
    return jsonify([user.username for user in users])