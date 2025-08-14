
import poetry

def install_dependency(dependency):
    if not isinstance(dependency, str) or not dependency.startswith("git+"):
        raise ValueError("Invalid dependency format. Must start with 'git+'.")

    escaped_dependency = dependency.replace("%", "%%")

    print(f"Attempting to install dependency: {dependency}")

    try:
        poetry.install(escaped_dependency)
    except Exception as e:
        print(f"Failed to install dependency: {e}")