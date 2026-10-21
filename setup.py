from setuptools import setup

setup(
    name="reconx",
    version="2.0",
    py_modules=["main"],
    packages=["modules"],
    install_requires=["pyyaml"],
    entry_points={
        "console_scripts": [
            "reconx=main:main",
        ],
    },
)
