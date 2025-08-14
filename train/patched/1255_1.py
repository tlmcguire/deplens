import os

def is_path_allowed(filepath, allowed_paths):
  """
  Checks if a filepath is allowed based on a list of allowed paths,
  with case-insensitive comparison.
  """
  normalized_filepath = os.path.normpath(filepath).lower()
  for allowed_path in allowed_paths:
    normalized_allowed_path = os.path.normpath(allowed_path).lower()
    if normalized_filepath.startswith(normalized_allowed_path):
      return True
  return False


if __name__ == '__main__':
  allowed_paths = ["/safe/path", "/another/safe/path"]

  blocked_path_normal = "/safe/path/sensitive.txt"

  bypass_path = "/SaFe/pAtH/sensitive.txt"


  print(f"Is '{blocked_path_normal}' allowed? {is_path_allowed(blocked_path_normal, allowed_paths)}")
  print(f"Is '{bypass_path}' allowed? {is_path_allowed(bypass_path, allowed_paths)}")

  unallowed_path = "/unsafe/path/sensitive.txt"
  print(f"Is '{unallowed_path}' allowed? {is_path_allowed(unallowed_path, allowed_paths)}")