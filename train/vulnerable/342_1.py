from marshmallow import Schema, fields

class UserSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    email = fields.Email(required=True)

user_role_only_fields = []

schema = UserSchema(only=user_role_only_fields)
data = {"username": "user1", "password": "secret", "email": "user1@example.com"}

result = schema.dump(data)
print(result)