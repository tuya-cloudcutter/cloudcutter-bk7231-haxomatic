"""A setuptools based setup module.
See:
https://packaging.python.org/guides/distributing-packages-using-setuptools/
https://github.com/pypa/sampleproject
Modified by Madoshakalaka@Github (dependency links added)
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
from os import path

# io.open is needed for projects that support Python 2.7
# It ensures open() defaults to text mode with universal newlines,
# and accepts an argument to specify the text encoding
# Python 3 only projects can skip this import
from io import open

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="cloudcutter-bk7231-haxomatic",
    version="0.0.1",
    description="Automatic payload builder for tuya-cloudcutter",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tuya-cloudcutter/cloudcutter-bk7231-haxomatic",
    author="tuya-cloudcutter",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    keywords="bk7231 cloudcutter tuya-cloudcutter",
    packages=find_packages(exclude=["contrib", "docs", "tests"]),
    python_requires=">=3.7",
    install_requires=['capstone==4.0.2'],
    entry_points={"console_scripts": ["haxomatic=haxomatic:main"]},
)
