import yaml
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class ExampleModel(Base):
    __tablename__ = 'example'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    value = Column(Integer)

def safe_load_yaml(fixture_text):
    return yaml.safe_load(fixture_text)

def load_fixtures(fixture_text):
    data = safe_load_yaml(fixture_text)
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    for item in data:
        new_item = ExampleModel(**item)
        session.add(new_item)
    session.commit()