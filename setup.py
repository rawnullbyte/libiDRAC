from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="libiDRAC",
    version="1.0.0",
    author="Nulla Baytu :3",
    author_email="me@nullbyte.rip",
    description="iDRAC vulnerability exploitation tool",
    long_description="long_description",
    long_description_content_type="text/markdown",
    url="https://github.com/rawnullbyte/libiDRAC",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    include_package_data=True,
    package_data={
        "idrac_exploit": ["payloads/*.c"],
    },
    entry_points={
        "console_scripts": [],
    },
)