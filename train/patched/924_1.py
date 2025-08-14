from packaging.version import parse as parse_version

def validate_package_name_and_version(package_name, version):
    if not version.startswith(package_name + '-'):
        raise ValueError("Package name does not match the version prefix.")

    try:
        parse_version(version)
    except Exception:
        raise ValueError("Invalid version format.")

try:
    validate_package_name_and_version("foo", "foo-2.0")
except ValueError as e:
    print(e)