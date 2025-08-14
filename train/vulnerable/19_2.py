import setuptools

setuptools.setup(
    name="malicious-package",
    version="0.0.1",
    description="A malicious package that exploits CVE-2022-40897",
    url="https://example.com/malicious-package",
    download_url="https://example.com/malicious.html",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=setuptools.find_packages(),
    python_requires=">=3.6",
)