def configure_data_pipeline(template):
    exec(template)

user_input_template = "print('Executing arbitrary code!')"
configure_data_pipeline(user_input_template)