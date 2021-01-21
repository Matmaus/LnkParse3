# LnkParse3

Windows Shortcut file (LNK) parser

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge)](http://makeapullrequest.com)
[![PyPI license](https://img.shields.io/pypi/l/LnkParse3.svg?style=for-the-badge)](https://github.com/Matmaus/LnkParse3/blob/master/LICENSE)
[![PyPi Version](https://img.shields.io/pypi/v/LnkParse3.svg?style=for-the-badge)](https://pypi.python.org/pypi/LnkParse3/)
[![PyPi Python Versions](https://img.shields.io/pypi/pyversions/LnkParse3.svg?style=for-the-badge)](https://pypi.python.org/pypi/LnkParse3/)
[![GitHub last commit](https://img.shields.io/github/last-commit/Matmaus/LnkParse3.svg?style=for-the-badge)](https://github.com/Matmaus/LnkParse3/commits/master)

LnkParse3 is a minimalistic python package for **forensics** of a binary file with [LNK](https://fileinfo.com/extension/lnk) extension aka [Microsoft Shell Link](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943) aka Windows shortcut. It is aimed to dig up as much data as possible and to process even **malformed files**. It is not able to create or modify files.

## Features

- easy to use
- CLI tool & package
- JSON output

# Background

This is a fork of `lnkfile` available [here](https://github.com/silascutler/LnkParse).

Improvements:

- much more extracted data
- many bug fixes
- made to not fail on malformed files

NOTE: `master` branch history was rewritten and has different commits metadata than the upstream `master`.

# Installation

```
pip install LnkParse3
```

# Usage

Can be used as a package or as a command line tool. It accepts several arguments, including setting the output format to JSON or a more human-readable form. For all parameters, see the program description below.

```
usage: lnkparse [-h] [-t] [-j] [-c CP] [-a] FILE

Windows Shortcut file (LNK) parser

positional arguments:
  FILE                  absolute or relative path to the file

optional arguments:
  -h, --help            show this help message and exit
  -t, --target          print target only
  -j, --json            print output in JSON
  -c CP, --codepage CP  set codepage of ASCII strings
  -a, --all             print all extracted data (i.e. offsets and sizes)
```

## CLI tool

```
$ lnkparse tests/microsoft_example
Windows Shortcut Information:
   Link CLSID: 00021401-0000-0000-C000-000000000046
   Link Flags: HasTargetIDList | HasLinkInfo | HasRelativePath | HasWorkingDir | IsUnicode | E
nableTargetMetadata - (524443)
   File Flags: FILE_ATTRIBUTE_ARCHIVE - (32)

   Creation Timestamp: 2008-09-12 20:27:17.101000+00:00
   Modified Timestamp: 2008-09-12 20:27:17.101000+00:00
   Accessed Timestamp: 2008-09-12 20:27:17.101000+00:00

   Icon Index: 0
   Window Style: SW_SHOWNORMAL
   HotKey: UNSET - UNSET {0x0000}

   ...more data...

   EXTRA BLOCKS:
      DISTRIBUTED_LINK_TRACKER_BLOCK
         Length: 88
         Version: 0
         Machine identifier: chris-xps
         Droid volume identifier: 94C77840-FA47-46C7-B356-5C2DC6B6D115
         Droid file identifier: 7BCD46EC-7F22-11DD-9499-00137216874A
         Birth droid volume identifier: 94C77840-FA47-46C7-B356-5C2DC6B6D115
         Birth droid file identifier: 7BCD46EC-7F22-11DD-9499-00137216874A
```

## Python package

```
>>> import LnkParse3
>>> with open('tests/samples/microsoft_example', 'rb') as indata:
>>> 	lnk = LnkParse3.lnk_file(indata)
>>> 	lnk.print_json()
{
	"data": {
        "relative_path": ".\\a.txt",
        "working_directory": "C:\\test"
    },
    "extra": {
        "DISTRIBUTED_LINK_TRACKER_BLOCK": {
            "birth_droid_file_identifier": "7BCD46EC-7F22-11DD-9499-00137216874A",
            "birth_droid_volume_identifier": "94C77840-FA47-46C7-B356-5C2DC6B6D115",
            "droid_file_identifier": "7BCD46EC-7F22-11DD-9499-00137216874A",
            "droid_volume_identifier": "94C77840-FA47-46C7-B356-5C2DC6B6D115",
            "length": 88,
            "machine_identifier": "chris-xps",
            "size": 96,
            "version": 0
        }
    },
	...more data...
}
```

# Contributing

Any contribution is welcome. There are still several uncovered parts of LNK Structure. Just fork the project and open a new PR.

## Tests

To run tests without installing any dependencies, just run:
``` sh
python -m unittest discover tests
```
If you want to use `pytest`, install it via `pip` and run:

``` sh
pytest tests
```
Also, to see code coverage in HTML output, run:
``` sh
pytest --cov=LnkParse3 tests --cov-fail-under=85 --cov-report=html --no-cov-on-fail
```

## Code

Make sure to run [`black`](https://pypi.org/project/black/) auto-formatter before opening a PR. It will keep the code in good shape.

Also, it would be nice to try to make meaningful commit messages and atomic commits.

# Authors and acknowledgment

Many thanks to the project's founder [@silascutler](https://github.com/silascutler) as well as to [@ernix](https://github.com/ernix) for such a good job refactoring and improving the code.

# Related projects

Here is a list of other available LNK parsers:

- [pylnk3](https://github.com/strayge/pylnk) - console application and package in Python 3
- [lnk-parse](https://github.com/lcorbasson/lnk-parse) - console application in Perl
- [pylnker](https://github.com/HarmJ0y/pylnker) - console application and package in Python 2, based on lnk-parse
- [liblnk](https://github.com/libyal/liblnk) - robust C library with Python 2/3 bindings

# License

Distributed under the MIT License. See [LICENSE](https://github.com/Matmaus/LnkParse3/blob/master/LICENSE) for more information.

# Contact

[matusjas.work@gmail.com](mailto:matusjas.work@gmail.com)

Source - [https://github.com/Matmaus/LnkParse3](https://github.com/Matmaus/LnkParse3)
