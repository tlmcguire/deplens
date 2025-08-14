import uuid

def local_uuid(deterministic=False, namespace=None):
    if deterministic and namespace is not None:
        return uuid.uuid5(namespace, "deterministic_string")
    else:
        return uuid.uuid4()

if __name__ == "__main__":
    print(local_uuid(deterministic=True, namespace=uuid.NAMESPACE_DNS))