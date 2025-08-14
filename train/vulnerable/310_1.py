
from setuptools import setup, find_packages

setup(
    name='d8s-file-system',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'democritus-hashes',
    ],
)