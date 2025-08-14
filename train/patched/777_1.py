def is_user_authorized(user, channel):
    authorized_users = get_authorized_users(channel)
    return user in authorized_users

def op_user(user, channel):
    if is_user_authorized(user, channel):
        channel.op(user)
    else:
        raise PermissionError("User  is not authorized to op in this channel.")

def voice_user(user, channel):
    if is_user_authorized(user, channel):
        channel.voice(user)
    else:
        raise PermissionError("User  is not authorized to voice in this channel.")