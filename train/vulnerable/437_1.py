from cookiecutter.main import cookiecutter

checkout = {"config": "alias.checkout=!touch ./HELLO"}
cookiecutter('some valid hg repository', checkout=checkout)