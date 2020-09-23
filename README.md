# LnkParse
Windows Shortcut file (LNK) parser

This is the fork of `lnkfile` available [here](https://github.com/silascutler/LnkParse)

Improvements:
* migrated to python 3
* more extracted data
* many bug fixes

See lnk format: https://msdn.microsoft.com/en-us/library/dd871305.aspx

Install:
`pip install LnkParse3`


# Example:
CLI tool
```
$ lnkparse -f tests/microsoft_example.lnk
Windows Shortcut Information:
	Link Flags: HasLinkInfo | EnableTargetMetadata | HasWorkingDir | IsUnicode | HasTargetIDList | HasRelativePath - (524443)
	File Flags: FILE_ATTRIBUTE_ARCHIVE - (32)

	Creation Timestamp: 2008-09-12 22:27:17
	Modified Timestamp: 2008-09-12 22:27:17
	Accessed Timestamp: 2008-09-12 22:27:17

	File Size: 0 (r: 459)
	Icon Index: 0 
	Window Style: SW_NORMAL 
	HotKey: UNSET -  {0x0000} 

	relativePath: .\a.txt
	workingDirectory: C:\test

	EXTRA BLOCKS:
		DISTRIBUTED_LINK_TRACKER_BLOCK
			[size] 96
			[length] 88
			[version] 0
			[machine_identifier] chris-xps
			[droid_volume_identifier] 4078c79447fac746b3565c2dc6b6d115
			[droid_file_identifier] ec46cd7b227fdd11949900137216874a
			[birth_droid_volume_identifier] 4078c79447fac746b3565c2dc6b6d115
			[birth_droid_file_identifier] ec46cd7b227fdd11949900137216874a
```

pip package
```
>>> import LnkParse3
>>> indata = open('tests/microsoft_example.lnk', 'rb')
>>> x = LnkParse3.lnk_file(indata)
>>> x.print_lnk_file()
Windows Shortcut Information:
	Link Flags: HasLinkInfo | EnableTargetMetadata | HasWorkingDir | IsUnicode | HasTargetIDList | HasRelativePath - (524443)
	File Flags: FILE_ATTRIBUTE_ARCHIVE - (32)

	Creation Timestamp: 2008-09-12 22:27:17
	Modified Timestamp: 2008-09-12 22:27:17
	Accessed Timestamp: 2008-09-12 22:27:17

	File Size: 0 (r: 459)
	Icon Index: 0 
	Window Style: SW_NORMAL 
	HotKey: UNSET -  {0x0000} 

	relativePath: .\a.txt
	workingDirectory: C:\test

	EXTRA BLOCKS:
		DISTRIBUTED_LINK_TRACKER_BLOCK
			[size] 96
			[length] 88
			[version] 0
			[machine_identifier] chris-xps
			[droid_volume_identifier] 4078c79447fac746b3565c2dc6b6d115
			[droid_file_identifier] ec46cd7b227fdd11949900137216874a
			[birth_droid_volume_identifier] 4078c79447fac746b3565c2dc6b6d115
			[birth_droid_file_identifier] ec46cd7b227fdd11949900137216874a

>>> x.print_json()
{
	"header": {
		"guid": "0114020000000000c000000000000046",
		"r_link_flags": 524443,
		"r_file_flags": 32,
		"creation_time": "2008-09-12 22:27:17",
		"accessed_time": "2008-09-12 22:27:17",
		"modified_time": "2008-09-12 22:27:17",
		"file_size": 0,
		"r_file_size": "00000000",
		"icon_index": 0,
		"windowstyle": "SW_NORMAL",
		"hotkey": "UNSET - UNSET {0x0000}",
		"r_hotkey": 0,
		"link_flags": [
			"HasTargetIDList",
			"HasLinkInfo",
			"HasRelativePath",
			"HasWorkingDir",
			"IsUnicode",
			"EnableTargetMetadata"
		],
		"file_flags": [
			"FILE_ATTRIBUTE_ARCHIVE"
		]
	},
	"data": {
		"relative_path": ".\\a.txt",
		"working_directory": "C:\\test"
	},
	"target": {
		"items": []
	},
	"link_info": {
		"link_info_flags": 1,
		"local_base_path": "C:\\test\\a.txt",
		"location": "Local",
		"location_info": {
			"volume_id_size": 17,
			"r_drive_type": 3,
			"drive_serial_number": "0x307a8a81",
			"volume_label_offset": 16,
			"drive_type": "DRIVE_FIXED",
			"volume_label": ""
		}
	},
	"extra": {
		"DISTRIBUTED_LINK_TRACKER_BLOCK": {
			"size": 96,
			"length": 88,
			"version": 0,
			"machine_identifier": "chris-xps",
			"droid_volume_identifier": "4078c79447fac746b3565c2dc6b6d115",
			"droid_file_identifier": "ec46cd7b227fdd11949900137216874a",
			"birth_droid_volume_identifier": "4078c79447fac746b3565c2dc6b6d115",
			"birth_droid_file_identifier": "ec46cd7b227fdd11949900137216874a"
		}
	}
}
```

