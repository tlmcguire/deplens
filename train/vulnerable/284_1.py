
from setuptools import setup

setup(
    name='d8s-pdfs',
    version='0.1.0',
    description='A package for handling PDFs with potential vulnerabilities',
    packages=['d8s_pdfs'],
    install_requires=[
        'democritus-urls',
    ],
)