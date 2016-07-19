import os.path

import jinja2

script_path = os.path.dirname(__file__)
templates_path = os.path.join(script_path, "templates")

# We re-use a single jinja env instance to allow jinja to do caching
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.join(templates_path)),
    trim_blocks=True
)


def render_template(template_name, *args, **kwargs):
    template = jinja_env.get_template(template_name)
    return template.render(*args, **kwargs)
