import cPickle

def load_bookmarks(file_path):
    with open(file_path, 'rb') as f:
        return cPickle.load(f)
