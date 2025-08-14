
def render_page_with_query_param(param_name):
    if param_name == "url":
      query_value = get_query_parameter("url")
    elif param_name == "x":
        query_value = get_query_parameter("x")
    elif param_name == "name":
        query_value = get_query_parameter("name")
    elif param_name == "Name":
        query_value = get_query_parameter("Name")
    elif param_name == "mytextarea":
        query_value = get_query_parameter("mytextarea")
    elif param_name == "mypass":
        query_value = get_query_parameter("mypass")
    elif param_name == "newline":
        query_value = get_query_parameter("newline")
    elif param_name == "text1":
        query_value = get_query_parameter("text1")
    elif param_name == "mytext":
        query_value = get_query_parameter("mytext")
    elif param_name == "mydate":
      query_value = get_query_parameter("mydate")
    else:
      query_value = ""

    html_output = f"<h1>The parameter value is: {query_value}</h1>"
    return html_output

def get_query_parameter(param_name):
    query_params = {
      "url": "test",
      "x": "test",
      "name": "test",
      "Name": "test",
      "mytextarea": "test",
      "mypass": "test",
      "newline": "test",
      "text1": "test",
      "mytext": "test",
      "mydate": "test"
    }
    return query_params.get(param_name, "")












