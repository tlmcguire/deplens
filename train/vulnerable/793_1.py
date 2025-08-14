from tuf import repository_tool

def download_root_metadata(repository):
    root_metadata = repository.get_root()

    print("Root metadata downloaded and trusted without verification.")

    return root_metadata

repository = repository_tool.create_new_repository('repository_path')
downloaded_root = download_root_metadata(repository)