import tuf.api.repo as tuf_repo
import os

repo = tuf_repo.Repository()

metadata_dir = 'metadata'
if not os.path.exists(metadata_dir):
    os.makedirs(metadata_dir)
repo.metadata_dir = metadata_dir

rolename = 'malicious_role'

role = repo.create_role(rolename)

role.add_target('target1', 'sha256:1234567890abcdef')

repo.writeall()