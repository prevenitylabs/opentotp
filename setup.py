import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="opentotp",
    version="1.0.0",
    description="Yet another Time-based, One-Time-Passwords Generator/Verifier",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/prevenitylabs/opentotp",
    author="Prevenity Labs",
    author_email="info@prevenity.com",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
    ],
    packages=["opentotp"],
    install_requires=["base58>=2.1.1"],
    entry_points={
        "console_scripts": [
            "opentotp=opentotp.__main__:main",
        ]
    },
)