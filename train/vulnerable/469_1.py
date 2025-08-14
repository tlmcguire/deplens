def process_data(data):
    for item in data:
        obj = create_object(item)
        ref_count = get_ref_count(obj)

        if ref_count > 1:
            free_object(obj)


def create_object(item):
    return item

def get_ref_count(obj):
    return 2

def free_object(obj):
    print(f"Freeing object: {obj}")