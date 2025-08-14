import kerberos

def check_password(service, user, password):
    try:
        result, context = kerberos.authGSSClientInit(service)

        kerberos.authGSSClientStep(context, "")




        while True:
          result = kerberos.authGSSClientStep(context, "")
          if result == 0:
             break


        if kerberos.authGSSClientResponse(context) != None:
          return True
        else:
          return False

    except kerberos.GSSError as e:
        print(f"Kerberos authentication error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False