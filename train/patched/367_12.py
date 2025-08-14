
import os
import sys

sys.path.insert(0, os.path.abspath('..'))




extensions = ['sphinx.ext.autodoc', 'sphinx.ext.autosummary']

templates_path = ['_templates']

source_suffix = '.rst'


master_doc = 'index'

project = 'python-jwt'
copyright = '2015, David Halls'

version = '3.3'
release = '3.3.4'



exclude_patterns = ['_build']





pygments_style = 'sphinx'





html_theme = 'nature'







html_static_path = ['_static']













htmlhelp_basename = 'python-jwtdoc'



latex_elements = {


}

latex_documents = [
  ('index', 'python-jwt.tex', 'python-jwt Documentation',
   'David Halls', 'manual'),
]









man_pages = [
    ('index', 'python-jwt', 'python-jwt Documentation',
     ['David Halls'], 1)
]




texinfo_documents = [
  ('index', 'python-jwt', 'python-jwt Documentation',
   'David Halls', 'python-jwt', 'One line description of project.',
   'Miscellaneous'),
]




