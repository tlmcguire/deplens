import pickle
import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, LargeBinary
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base



Base = declarative_base()

class YourModel(Base):
    __tablename__ = 'your_table'
    id = Column(Integer, primary_key=True)
    data = Column(LargeBinary)


def safe_load(data):
    allowed_classes = (dict, list, str, int, float, bool)
    obj = pickle.loads(data)

    if not isinstance(obj, allowed_classes):
        raise ValueError("Unsafe object type detected!")

    return obj

def persist_safe_object(obj, session):
    safe_data = pickle.dumps(obj)

    new_entry = YourModel(data=safe_data)
    session.add(new_entry)
    session.commit()

try:
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    user_input = {'key': 'value'}
    persist_safe_object(user_input, session)
    session.close()
except Exception as e:
    print(f"Error: {e}")