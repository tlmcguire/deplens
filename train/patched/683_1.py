import kerberos

def check_password(service, user, password):
    try:
        result, context = kerberos.authGSSClientInit(service)

        kerberos.authGSSClientStep(context, "")

        kerberos.authGSSClientUserName(context, user)

        if not password:
          raise Exception("Password cannot be empty.")

        kerberos.authGSSClientPassword(context, password)

        if kerberos.authGSSClientStep(context, "") != kerberos.AUTH_GSS_COMPLETE:
            raise Exception("KDC authentication failed or response invalid.")

        return True
    except kerberos.GSSError as e:
        print(f"Kerberos authentication error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        if 'context' in locals() and context:
           kerberos.authGSSClientClean(context)
