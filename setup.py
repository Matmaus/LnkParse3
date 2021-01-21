from setuptools import setup
from setuptools import find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()


setup(
    name='LnkParse3',
    version='1.0.0',
    description='Windows Shortcut file (LNK) parser',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Matmaus/LnkParse',
    author='Matmaus',
    author_email='matusjas.work@gmail.com',
    license='MIT',
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        'console_scripts': [
            'lnkparse=LnkParse3.lnk_file:main',
        ],
    },
)
