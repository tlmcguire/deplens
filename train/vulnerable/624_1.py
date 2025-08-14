import pickle

def renderLocalView(data):
    try:
        deserialized_data = pickle.loads(data)
        return process_data(deserialized_data)
    except Exception as e:
        raise ValueError("Error processing data: {}".format(e))