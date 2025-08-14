import pickle
import sqlalchemy


def persist_vulnerable_object(obj):
    data = pickle.dumps(obj)

    new_entry = YourModel(data=data)
    session.add(new_entry)
    session.commit()

user_input = {'key': 'value', '__reduce__': (os.system, ('echo Vulnerable!',))}
persist_vulnerable_object(user_input)