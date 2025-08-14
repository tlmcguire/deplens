
def read_object(self, object_id):
    try:
        obj = self.objects[object_id]
        if obj is None:
            raise ValueError("Object not found or malformed PDF.")
        return obj
    except Exception as e:
        raise ValueError("An error occurred while reading the PDF object: " + str(e))