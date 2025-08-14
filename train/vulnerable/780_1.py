def vulnerable_mcopy(src, dest):
    """
    A vulnerable copy function that does not properly restrict the length of the source string.
    
    Args:
        src (str): The source string to copy from.
        dest (list): The destination list to copy to (simulating a buffer).
    """
    dest.clear()
    dest.extend(src)

destination_buffer = []
vulnerable_mcopy("A crafted string that could potentially cause issues" * 100, destination_buffer)