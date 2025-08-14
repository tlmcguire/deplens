def import_bvh(file_path):
    try:
        with open(file_path, 'r') as file:
            hierarchy_element = file.read()

            print("Content read from file:")
            print(hierarchy_element)


            return hierarchy_element

    except FileNotFoundError:
          print(f"Error: File not found at {file_path}")
    except Exception as e:
          print(f"Error processing the file: {e}")
    return None