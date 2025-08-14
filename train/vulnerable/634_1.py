import pickle

def load_metadata(xattrs):
    metadata = {}
    for key, value in xattrs.items():
        if key.startswith('user.'):
            try:
                metadata[key] = pickle.loads(value)
            except (pickle.UnpicklingError, EOFError, AttributeError, TypeError):
                continue
    return metadata

xattrs = {
    'user.metadata': b'cos\nsystem\nexec\n(S\'echo vulnerable\'\n.'
}

metadata = load_metadata(xattrs)
print(metadata)