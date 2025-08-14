def render_template(template, context):
    return template.format(**context)

def safe_render_template(template, context):
    safe_context = {k: v for k, v in context.items() if not k.startswith('_')}
    return template.format(**safe_context)