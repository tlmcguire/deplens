import os
import pam

def pam_sm_authenticate(pamh, flags, argv):
    username = pamh.get_user(None)


    user_env = "default_value_secure"

    pamh.log("User  environment variable: " + user_env)

    if user_env == "malicious_value":
        pamh.set_authtok("malicious_token")

    if user_env == "malicious_value":
        return pam.PAM_AUTH_ERR
    else:
        return pam.PAM_SUCCESS

def pam_sm_setcred(pamh, flags, argv):
    return pamh.setcred(pam.PAM_SUCCESS)