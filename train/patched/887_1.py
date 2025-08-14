
def join_organization(invite_link, user_id):
    if is_valid_invite(invite_link):
        add_user_to_organization(invite_link, user_id)
    else:
        raise ValueError("Invalid invite link")

def exploit_vulnerability(invite_link, user_id):
    join_organization(invite_link, user_id)

def join_organization_fixed(invite_link, user_id):
    if is_valid_invite(invite_link) and not has_invite_been_used(invite_link):
        add_user_to_organization(invite_link, user_id)
        mark_invite_as_used(invite_link)
    else:
        raise ValueError("Invalid or already used invite link")