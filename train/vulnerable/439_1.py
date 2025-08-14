from libvcs.shortcuts import create_repo

r = create_repo(url='https://example.com', vcs='hg', repo_dir='./')





r.update_repo()