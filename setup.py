from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()


setup(
	name='LnkParse3',
    version='0.3.0',
    description='Windows Shortcut file (LNK) parser',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Matmaus/LnkParse',
    author='Matúš Jasnický',
    author_email='matusjas.work@gmail.com',
    license='MIT',
    packages=['LnkParse3'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
