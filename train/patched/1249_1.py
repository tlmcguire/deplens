import jinja2
from markupsafe import Markup

def render_template_safely(template_string, context):
  """Renders a Jinja2 template with a safe environment."""

  env = jinja2.Environment(
      autoescape=True,
      loader=jinja2.DictLoader({'template': template_string}),
  )


  def sandbox_policy(obj):
    if isinstance(obj, str) and "__" in obj:
      raise jinja2.TemplateError(f"Accessing attributes starting with '__' is not permitted.")
    return obj

  env.filters["safe_filter"] = sandbox_policy
  env.globals["safe_filter"] = sandbox_policy


  template = env.get_template("template")

  safe_context = {k: Markup(v) if isinstance(v, str) else v for k, v in context.items()}

  return template.render(safe_context)


if __name__ == '__main__':

    template_string = "<h1>Report: {{ title }}</h1> <p>Description: {{ description }}</p> "
    user_supplied_title = "<script>alert('XSS');</script>"
    user_supplied_description = "{{ config }}"

    context = {
        "title": user_supplied_title,
        "description": user_supplied_description,
    }

    safe_output = render_template_safely(template_string, context)
    print(f"Safe Output:\n{safe_output}")




    template_string_no_escape = "<h1>Report: {{ title }}</h1> <p>Description: {{ description | safe }}</p> "
    user_supplied_title = "<script>alert('XSS');</script>"
    user_supplied_description = "{{ config }}"

    context = {
        "title": user_supplied_title,
        "description": user_supplied_description,
    }

    safe_output = render_template_safely(template_string_no_escape, context)
    print(f"Safe Output with no escape filter:\n{safe_output}")



    template_string_malicious = "<p>{{ malicious_payload | safe_filter}} </p>"
    user_supplied_malicious_payload = "{{ self.class.mro[1].subclasses()[462]('calc')() }}"

    context = {
      "malicious_payload": user_supplied_malicious_payload,
    }

    try:
        safe_output = render_template_safely(template_string_malicious, context)
        print(f"Malicious payload output:{safe_output}")
    except jinja2.TemplateError as e:
        print(f"Malicious Payload blocked: {e}")