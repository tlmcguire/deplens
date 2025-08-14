import yaml

def load_fixtures(fixture_text):
    data = yaml.load(fixture_text, Loader=yaml.FullLoader)
    for item in data:
        save_to_database(item)