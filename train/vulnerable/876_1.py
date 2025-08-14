from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, auth_token_required
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.config['SECRET_KEY'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False

db = SQLAlchemy(app)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(length=80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(length=255), unique=True)
    password = db.Column(db.String(length=255))
    active = db.Column(db.Boolean())
    roles = db.relationship('Role', secondary='roles_users',
                            backref=db.backref('users', lazy='dynamic'))

    def __init__(self, **kwargs):
       super(User, self).__init__(**kwargs)
       if self.password:
           self.password = generate_password_hash(self.password)


    def verify_password(self, password):
        return check_password_hash(self.password, password)


roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
        )

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    user = user_datastore.find_user(email=email)

    if user and user.verify_password(password):
        return jsonify({"token": "user_authentication_token"})

    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/change', methods=['POST'])
@auth_token_required
def change():
    return jsonify({"message":"Change successful"})

@app.route('/register', methods=['POST'])
def register():
    email = request.json.get('email')
    password = request.json.get('password')
    user = user_datastore.create_user(email=email, password=password)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.before_first_request
def create_user():
    db.create_all()
    if not user_datastore.find_user(email='test@test.com'):
        user_datastore.create_user(email='test@test.com', password='password')
        db.session.commit()


if __name__ == '__main__':
    app.run(debug=True)