from cookiecutter.main import cookiecutter

checkout = "--config=alias.checkout=--"
cookiecutter('some valid hg repository', checkout=checkout)