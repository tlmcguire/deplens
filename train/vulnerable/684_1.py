from setuptools import setup, find_packages

setup(
    name='example_package',
    version='1.0',
    packages=find_packages(),
    install_requires=[
        'numpy',
        'scipy',
    ]
)