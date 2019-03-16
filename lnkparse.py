#!/usr/bin/env python
# By Silas Cutler
#    silas.cutler@blacklistthisdomain.com

__description__ = 'Windows Shortcut file (LNK) parser'
__author__ = 'Silas Cutler'
__version__ = '0.2.1'

import sys
import lnkfile
import argparse


def main():
	arg_parser = argparse.ArgumentParser(description=__description__)
	arg_parser.add_argument('-f', '--file', dest='file', required=True,
							help='absolute or relative path to the file')
	arg_parser.add_argument('-j', '--json', action='store_true',
							help='print output in JSON')
	arg_parser.add_argument('-d', '--json_debug', action='store_true',
							help='print all extracted data in JSON (i.e. offsets and sizes)')
	arg_parser.add_argument('-D', '--debug', action='store_true',
							help='print debug info')
	args = arg_parser.parse_args()

	with open(args.file, 'rb') as file:
		lnk = lnkfile.lnk_file(fhandle=file, debug=args.debug)
		if args.json:
			lnk.print_json(args.json_debug)
		else:
			lnk.print_lnk_file()


if __name__ == "__main__":
	main()
