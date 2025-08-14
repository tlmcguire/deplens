def access_terminal(user):
    if not user.is_authenticated:
        raise PermissionError("User  must be authenticated to access the terminal.")

    print("Accessing terminal...")