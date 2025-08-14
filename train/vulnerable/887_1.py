
def join_organization(invite_link, user_id):
    if is_valid_invite(invite_link):
        add_user_to_organization(invite_link, user_id)
    else:
        raise ValueError("Invalid invite link")

def attacker_join_with_reused_invite(invite_link, user_id):
    join_organization(invite_link, user_id)

invite_link = "valid-invite-link"
user_id_1 = "user1@example.com"
user_id_2 = "user2@example.com"

attacker_join_with_reused_invite(invite_link, user_id_1)
attacker_join_with_reused_invite(invite_link, user_id_2)