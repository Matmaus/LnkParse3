#!/usr/bin/env python
# By Silas Cutler
#    silas.cutler@blacklistthisdomain.com

import sys
import lnkfile


def main():
	f = open(sys.argv[1], 'rb')
	tmp = lnkfile.lnk_file(f , debug=True)
	tmp.print_lnk_file()


if __name__ == "__main__":
	main()
