#!/usr/bin/env python3

__description__ = 'Windows Shortcut file (LNK) parser'
__author__ = 'Matúš Jasnický'
__version__ = '0.3.0'

import json
import struct
import datetime
import argparse


class lnk_file(object):
	def __init__(self, fhandle=None, indata=None, debug=False):
		self.define_static()

		if fhandle:
			self.indata = fhandle.read()
		elif indata:
			self.indata = indata

		self.debug = debug
		self.lnk_header = {}

		self.linkFlag = {
			'HasTargetIDList': False,
			'HasLinkInfo': False,
			'HasName': False,
			'HasRelativePath': False,
			'HasWorkingDir': False,
			'HasArguments': False,
			'HasIconLocation': False,
			'IsUnicode': False,
			'ForceNoLinkInfo': False,
			'HasExpString': False,
			'RunInSeparateProcess': False,
			'Reserved0': False,
			'HasDarwinID': False,
			'RunAsUser': False,
			'HasExpIcon': False,
			'NoPidlAlias': False,
			'Reserved1': False,
			'RunWithShimLayer': False,
			'ForceNoLinkTrack': False,
			'EnableTargetMetadata': False,
			'DisableLinkPathTracking': False,
			'DisableKnownFolderTracking': False,
			'DisableKnownFolderAlias': False,
			'AllowLinkToLink': False,
			'UnaliasOnSave': False,
			'PreferEnvironmentPath': False,
			'KeepLocalIDListForUNCTarget': False,
		}
		self.fileFlag = {
			'FILE_ATTRIBUTE_READONLY': False,
			'FILE_ATTRIBUTE_HIDDEN': False,
			'FILE_ATTRIBUTE_SYSTEM': False,
			'Reserved, not used by the LNK format': False,
			'FILE_ATTRIBUTE_DIRECTORY': False,
			'FILE_ATTRIBUTE_ARCHIVE': False,
			'FILE_ATTRIBUTE_DEVICE': False,
			'FILE_ATTRIBUTE_NORMAL': False,
			'FILE_ATTRIBUTE_TEMPORARY': False,
			'FILE_ATTRIBUTE_SPARSE_FILE': False,
			'FILE_ATTRIBUTE_REPARSE_POINT': False,
			'FILE_ATTRIBUTE_COMPRESSED': False,
			'FILE_ATTRIBUTE_OFFLINE': False,
			'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED': False,
			'FILE_ATTRIBUTE_ENCRYPTED': False,
			'Unknown (seen on Windows 95 FAT)': False,
			'FILE_ATTRIBUTE_VIRTUAL': False,
		}

		self.targets = {
			'size': 0,
			'items': [],
		}

		self.loc_information = {}
		self.data = {}
		self.extraBlocks = {}

		self.process()
		self.define_common()


	def define_common(self):
		try:
			out = ''
			if self.linkFlag['HasRelativePath']:
				out += self.data['relative_path']
			if self.linkFlag['HasArguments']:
				out += ' ' + self.data['command_line_arguments']

			self.lnk_command = out
		except Exception as e:
			if self.debug:
				print('Exception define_common: %s' % e)


	def get_command(self):
		try:
			out = ''
			if self.linkFlag['HasRelativePath']:
				out += self.data['relative_path']
			if self.linkFlag['HasArguments']:
				out += ' ' + self.data['command_line_arguments']

			return out
		except Exception as e:
			if self.debug:
				print('Exception get_command: %s' % (e))
			return ''


	def define_static(self):
		# Define static constents used within the LNK format

		# Each MAGIC string refernces a function for processing
		self.EXTRA_SIGS = {
			'a0000001': self.parse_environment_block,
			'a0000002': self.parse_console_block,
			'a0000003': self.parse_distributedTracker_block,
			'a0000004': self.parse_codepage_block,
			'a0000005': self.parse_specialFolder_block,
			'a0000006': self.parse_darwin_block,
			'a0000007': self.parse_icon_block,
			'a0000008': self.parse_shimLayer_block,
			'a0000009': self.parse_metadata_block,
			'a000000b': self.parse_knownFolder_block,
			'a000000c': self.parse_shellItem_block,
		}

		self.DRIVE_TYPES = [
			'DRIVE_UNKNOWN',
			'DRIVE_NO_ROOT_DIR',
			'DRIVE_REMOVABLE',
			'DRIVE_FIXED',
			'DRIVE_REMOTE',
			'DRIVE_CDROM',
			'DRIVE_RAMDISK',
		]
		self.HOTKEY_VALUES_HIGH = {
			'\x00': 'UNSET',
			'\x01': 'SHIFT',
			'\x02': 'CONTROL',
			'\x03': 'ALT',
		}
		self.HOTKEY_VALUES_LOW = {
			'\x00': 'UNSET',
			'\x30': '0',
			'\x31': '1',
			'\x32': '2',
			'\x33': '3',
			'\x34': '4',
			'\x35': '5',
			'\x36': '6',
			'\x37': '7',
			'\x38': '8',
			'\x39': '9',
			'\x41': 'A',
			'\x42': 'B',
			'\x43': 'C',
			'\x44': 'D',
			'\x45': 'E',
			'\x46': 'F',
			'\x47': 'G',
			'\x48': 'H',
			'\x49': 'I',
			'\x4A': 'J',
			'\x4B': 'K',
			'\x4C': 'L',
			'\x4D': 'M',
			'\x4E': 'N',
			'\x4F': 'O',
			'\x50': 'P',
			'\x51': 'Q',
			'\x52': 'R',
			'\x53': 'S',
			'\x54': 'T',
			'\x55': 'U',
			'\x56': 'V',
			'\x57': 'W',
			'\x58': 'X',
			'\x59': 'Y',
			'\x5A': 'Z',
			'\x70': 'F1',
			'\x71': 'F2',
			'\x72': 'F3',
			'\x73': 'F4',
			'\x74': 'F5',
			'\x75': 'F6',
			'\x76': 'F7',
			'\x77': 'F8',
			'\x78': 'F9',
			'\x79': 'F10',
			'\x7A': 'F11',
			'\x7B': 'F12',
			'\x7C': 'F13',
			'\x7D': 'F14',
			'\x7E': 'F15',
			'\x7F': 'F16',
			'\x80': 'F17',
			'\x81': 'F18',
			'\x82': 'F19',
			'\x83': 'F20',
			'\x84': 'F21',
			'\x85': 'F22',
			'\x86': 'F23',
			'\x87': 'F24',
			'\x90': 'NUM_LOCK',
			'\x91': 'SCROLL_LOCK',
		}
		self.WINDOWSTYLES = [
			'SW_HIDE',
			'SW_NORMAL',
			'SW_SHOWMINIMIZED',
			'SW_MAXIMIZE ',
			'SW_SHOWNOACTIVATE',
			'SW_SHOW',
			'SW_MINIMIZE',
			'SW_SHOWMINNOACTIVE',
			'SW_SHOWNA',
			'SW_RESTORE',
			'SW_SHOWDEFAULT',
		]


	@staticmethod
	def clean_line(rstring):
		return ''.join(chr(i) for i in rstring if 128 > i > 20)


	def parse_lnk_header(self):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                             <u_int32> HeaderSize == 0x0000004C                                 |
		--------------------------------------------------------------------------------------------------
		|                   <CSID> LinkCLSID == 00021401-0000-0000-C000-000000000046                     |
		|                                            16 B                                                |
		--------------------------------------------------------------------------------------------------
		|                                     <flags> LinkFlags                                          |
		--------------------------------------------------------------------------------------------------
		|                                   <flags> FileAttributes                                       |
		--------------------------------------------------------------------------------------------------
		|                                  <FILETIME> CreationTime                                       |
		|                                            16 B                                                |
		--------------------------------------------------------------------------------------------------
		|                                   <FILETIME> AccessTime                                        |
		|                                            16 B                                                |
		--------------------------------------------------------------------------------------------------
		|                                   <FILETIME> WriteTime                                         |
		|                                            16 B                                                |
		--------------------------------------------------------------------------------------------------
		|                                   <u_int32> FileSize                                           |
		--------------------------------------------------------------------------------------------------
		|                                   <int32> IconIndex                                            |
		--------------------------------------------------------------------------------------------------
		|                                 <u_int32> ShowCommand                                          |
		--------------------------------------------------------------------------------------------------
		|           <HotKeyFlags> HotKey              |                    Reserved1                     |
		--------------------------------------------------------------------------------------------------
		|                                        Reserved2                                               |
		--------------------------------------------------------------------------------------------------
		|                                        Reserved3                                               |
		--------------------------------------------------------------------------------------------------
		"""
		# Parse the LNK file header
		try:
			# Header always starts with { 4c 00 00 00 } and is the size of the header
			self.lnk_header['header_size'] = struct.unpack('<I', self.indata[:4])[0]

			lnk_header = self.indata[:self.lnk_header['header_size']]

			self.lnk_header['guid'] = lnk_header[4:20].hex()

			self.lnk_header['r_link_flags'] = struct.unpack('<i', lnk_header[20:24])[0]
			self.lnk_header['r_file_flags'] = struct.unpack('<i', lnk_header[24:28])[0]

			self.lnk_header['creation_time'] = struct.unpack('<q', lnk_header[28:36])[0]
			self.lnk_header['accessed_time'] = struct.unpack('<q', lnk_header[36:44])[0]
			self.lnk_header['modified_time'] = struct.unpack('<q', lnk_header[44:52])[0]

			self.lnk_header['file_size'] = struct.unpack('<i', lnk_header[52:56])[0]
			self.lnk_header['r_file_size'] = lnk_header[52:56].hex()

			self.lnk_header['icon_index'] = struct.unpack('<I', lnk_header[56:60])[0]
			try:
				if struct.unpack('<i', lnk_header[60:64])[0] < len(self.WINDOWSTYLES):
					self.lnk_header['windowstyle'] = self.WINDOWSTYLES[
						struct.unpack('<i', lnk_header[60:64])[0]]
				else:
					self.lnk_header['windowstyle'] = struct.unpack('<i', lnk_header[60:64])[0]
			except Exception as e:
				if self.debug:
					print('Error Parsing WindowStyle in Header: %s' % e)
				self.lnk_header['windowstyle'] = struct.unpack('<i', lnk_header[60:64])[0]

			try:
				self.lnk_header['hotkey'] = '%s - %s {0x%s}' % (
					self.HOTKEY_VALUES_HIGH[chr(struct.unpack('<B', lnk_header[65:66])[0])],
					self.HOTKEY_VALUES_LOW[chr(struct.unpack('<B', lnk_header[64:65])[0])],
					lnk_header[64:66].hex()
				)

				self.lnk_header['r_hotkey'] = struct.unpack('<H', lnk_header[64:66])[0]
			except Exception as e:
				if self.debug:
					print('Exception parsing HOTKEY part of header: %s' % e)
					print(lnk_header[65:66].hex())
				self.lnk_header['hotkey'] = hex(struct.unpack('<H', lnk_header[64:66])[0])
				self.lnk_header['r_hotkey'] = struct.unpack('<H', lnk_header[64:66])[0]

			self.lnk_header['reserved0'] = struct.unpack('<H', lnk_header[66:68])[0]
			self.lnk_header['reserved1'] = struct.unpack('<i', lnk_header[68:72])[0]
			self.lnk_header['reserved2'] = struct.unpack('<i', lnk_header[72:76])[0]
		except Exception as e:
			if self.debug:
				print('Exception parsing LNK Header: %s' % e)
			return False

		if self.lnk_header['header_size'] == 76:
			return True


	def parse_link_flags(self):
		if self.lnk_header['r_link_flags'] & 0x00000001:
			self.linkFlag['HasTargetIDList'] = True
		if self.lnk_header['r_link_flags'] & 0x00000002:
			self.linkFlag['HasLinkInfo'] = True
		if self.lnk_header['r_link_flags'] & 0x00000004:
			self.linkFlag['HasName'] = True
		if self.lnk_header['r_link_flags'] & 0x00000008:
			self.linkFlag['HasRelativePath'] = True
		if self.lnk_header['r_link_flags'] & 0x00000010:
			self.linkFlag['HasWorkingDir'] = True
		if self.lnk_header['r_link_flags'] & 0x00000020:
			self.linkFlag['HasArguments'] = True
		if self.lnk_header['r_link_flags'] & 0x00000040:
			self.linkFlag['HasIconLocation'] = True
		if self.lnk_header['r_link_flags'] & 0x00000080:
			self.linkFlag['IsUnicode'] = True
		if self.lnk_header['r_link_flags'] & 0x00000100:
			self.linkFlag['ForceNoLinkInfo'] = True
		if self.lnk_header['r_link_flags'] & 0x00000200:
			self.linkFlag['HasExpString'] = True
		if self.lnk_header['r_link_flags'] & 0x00000400:
			self.linkFlag['RunInSeparateProcess'] = True
		if self.lnk_header['r_link_flags'] & 0x00000800:
			self.linkFlag['Reserved0'] = True
		if self.lnk_header['r_link_flags'] & 0x00001000:
			self.linkFlag['HasDarwinID'] = True
		if self.lnk_header['r_link_flags'] & 0x00002000:
			self.linkFlag['RunAsUser'] = True
		if self.lnk_header['r_link_flags'] & 0x00004000:
			self.linkFlag['HasExpIcon'] = True
		if self.lnk_header['r_link_flags'] & 0x00008000:
			self.linkFlag['NoPidlAlias'] = True
		if self.lnk_header['r_link_flags'] & 0x000100000:
			self.linkFlag['Reserved1'] = True

		if self.lnk_header['r_link_flags'] & 0x00020000:
			self.linkFlag['RunWithShimLayer'] = True
		if self.lnk_header['r_link_flags'] & 0x00040000:
			self.linkFlag['ForceNoLinkTrack'] = True
		if self.lnk_header['r_link_flags'] & 0x00080000:
			self.linkFlag['EnableTargetMetadata'] = True
		if self.lnk_header['r_link_flags'] & 0x00100000:
			self.linkFlag['DisableLinkPathTracking'] = True
		if self.lnk_header['r_link_flags'] & 0x00200000:
			self.linkFlag['DisableKnownFolderTracking'] = True
		if self.lnk_header['r_link_flags'] & 0x00400000:
			self.linkFlag['DisableKnownFolderAlias'] = True
		if self.lnk_header['r_link_flags'] & 0x00800000:
			self.linkFlag['AllowLinkToLink'] = True
		if self.lnk_header['r_link_flags'] & 0x01000000:
			self.linkFlag['UnaliasOnSave'] = True
		if self.lnk_header['r_link_flags'] & 0x02000000:
			self.linkFlag['PreferEnvironmentPath'] = True
		if self.lnk_header['r_link_flags'] & 0x04000000:
			self.linkFlag['KeepLocalIDListForUNCTarget'] = True

		self.lnk_header['link_flags'] = self.enabled_flags_to_list(self.linkFlag)


	def parse_file_flags(self):
		if self.lnk_header['r_file_flags'] & 0x00000001:
			self.fileFlag['FILE_ATTRIBUTE_READONLY'] = True
		if self.lnk_header['r_file_flags'] & 0x00000002:
			self.fileFlag['FILE_ATTRIBUTE_HIDDEN'] = True
		if self.lnk_header['r_file_flags'] & 0x00000004:
			self.fileFlag['FILE_ATTRIBUTE_SYSTEM'] = True
		if self.lnk_header['r_file_flags'] & 0x00000008:
			self.fileFlag['Reserved, not used by the LNK format'] = True
		if self.lnk_header['r_file_flags'] & 0x00000010:
			self.fileFlag['FILE_ATTRIBUTE_DIRECTORY'] = True
		if self.lnk_header['r_file_flags'] & 0x00000020:
			self.fileFlag['FILE_ATTRIBUTE_ARCHIVE'] = True
		if self.lnk_header['r_file_flags'] & 0x00000040:
			self.fileFlag['FILE_ATTRIBUTE_DEVICE'] = True
		if self.lnk_header['r_file_flags'] & 0x00000080:
			self.fileFlag['FILE_ATTRIBUTE_NORMAL'] = True
		if self.lnk_header['r_file_flags'] & 0x00000100:
			self.fileFlag['FILE_ATTRIBUTE_TEMPORARY'] = True
		if self.lnk_header['r_file_flags'] & 0x00000200:
			self.fileFlag['FILE_ATTRIBUTE_SPARSE_FILE'] = True
		if self.lnk_header['r_file_flags'] & 0x00000400:
			self.fileFlag['FILE_ATTRIBUTE_REPARSE_POINT'] = True
		if self.lnk_header['r_file_flags'] & 0x00000800:
			self.fileFlag['FILE_ATTRIBUTE_COMPRESSED'] = True
		if self.lnk_header['r_file_flags'] & 0x00001000:
			self.fileFlag['FILE_ATTRIBUTE_OFFLINE'] = True
		if self.lnk_header['r_file_flags'] & 0x00002000:
			self.fileFlag['FILE_ATTRIBUTE_NOT_CONTENT_INDEXED'] = True
		if self.lnk_header['r_file_flags'] & 0x00004000:
			self.fileFlag['FILE_ATTRIBUTE_ENCRYPTED'] = True
		if self.lnk_header['r_file_flags'] & 0x00008000:
			self.fileFlag['Unknown (seen on Windows 95 FAT)'] = True
		if self.lnk_header['r_file_flags'] & 0x00010000:
			self.fileFlag['FILE_ATTRIBUTE_VIRTUAL'] = True

		self.lnk_header['file_flags'] = self.enabled_flags_to_list(self.fileFlag)


	def parse_link_information(self, index):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                                   <u_int32> LinkInfoSize                                       |
		--------------------------------------------------------------------------------------------------
		|                                <u_int32> LinkInfoHeaderSize                                    |
		--------------------------------------------------------------------------------------------------
		|                                   <flags> LinkInfoFlags                                        |
		--------------------------------------------------------------------------------------------------
		|                                  <u_int32> VolumeIDOffset                                      |
		--------------------------------------------------------------------------------------------------
		|                               <u_int32> LocalBasePathOffset                                    |
		--------------------------------------------------------------------------------------------------
		|                           <u_int32> CommonNetworkRelativeLinkOffset                            |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> CommonPathSuffixOffset                                  |
		--------------------------------------------------------------------------------------------------
		|                        <u_int32> LocalBasePathOffsetUnicode (optional)                         |
		--------------------------------------------------------------------------------------------------
		|                       <u_int32> CommonPathSuffixOffsetUnicode (optional)                       |
		--------------------------------------------------------------------------------------------------
		|                                 <VolumeID> VolumeID (optional)                                 |
		|                                            ? B                                                 |
		--------------------------------------------------------------------------------------------------
		|                                 <str> LocalBasePath (optional)                                 |
		|                                            ? B                                                 |
		--------------------------------------------------------------------------------------------------
		|              <CommonNetworkRelativeLink> CommonNetworkRelativeLink (optional)                  |
		|                                            ? B                                                 |
		--------------------------------------------------------------------------------------------------
		|                               <str> CommonPathSuffix (optional)                                |
		|                                            ? B                                                 |
		--------------------------------------------------------------------------------------------------
		|                        <unicode_str> LocalBasePathUnicode (optional)                           |
		|                                            ? B                                                 |
		--------------------------------------------------------------------------------------------------
		|                      <unicode_str> CommonPathSuffixUnicode (optional)                          |
		|                                            ? B                                                 |
		--------------------------------------------------------------------------------------------------
		"""
		self.loc_information = {
			'link_info_size': struct.unpack('<i', self.indata[index: index + 4])[0],
			'link_info_header_size': struct.unpack('<i', self.indata[index + 4: index + 8])[0],
			'link_info_flags': struct.unpack('<i', self.indata[index + 8: index + 12])[0],
			'volume_id_offset': struct.unpack('<i', self.indata[index + 12: index + 16])[0],
			'local_base_path_offset': struct.unpack('<i', self.indata[index + 16: index + 20])[0],
			'common_network_relative_link_offset': struct.unpack('<i', self.indata[index + 20: index + 24])[0],
			'common_path_suffix_offset': struct.unpack('<i', self.indata[index + 24: index + 28])[0],
		}

		if self.loc_information['link_info_flags'] & 0x0001:
			"""
			--------------------------------------------------------------------------------------------------
			|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
			--------------------------------------------------------------------------------------------------
			|                                   <u_int32> VolumeIDSize                                       |
			--------------------------------------------------------------------------------------------------
			|                                    <u_int32> DriveType                                         |
			--------------------------------------------------------------------------------------------------
			|                                 <u_int32> DriveSerialNumber                                    |
			--------------------------------------------------------------------------------------------------
			|                                 <u_int32> VolumeLabelOffset                                    |
			--------------------------------------------------------------------------------------------------
			|                        <u_int32> VolumeLabelOffsetUnicode (optional)                           |
			--------------------------------------------------------------------------------------------------
			|                                       <u_int32> Data                                           |
			|                                            ? B                                                 |
			--------------------------------------------------------------------------------------------------
			"""
			if self.loc_information['link_info_header_size'] >= 36:
				self.loc_information['o_local_base_path_offset_unicode'] = \
						struct.unpack('<i', self.indata[index + 28: index + 32])[0]
				local_index = index + self.loc_information['o_local_base_path_offset_unicode']
				self.loc_information['o_local_base_path_offset_unicode'] = \
						struct.unpack('<i', self.indata[local_index: local_index + 4])[0]
			else:
				local_index = index + self.loc_information['local_base_path_offset']
				self.loc_information['local_base_path'] = self.read_string(local_index)

			local_index = index + self.loc_information['volume_id_offset']
			self.loc_information['location'] = 'Local'
			self.loc_information['location_info'] = {
				'volume_id_size':
					struct.unpack('<I', self.indata[local_index + 0: local_index + 4])[0],
				'r_drive_type':
					struct.unpack('<I', self.indata[local_index + 4: local_index + 8])[0],
				'drive_serial_number': hex(
					struct.unpack('<I', self.indata[local_index + 8: local_index + 12])[0]),
				'volume_label_offset':
					struct.unpack('<I', self.indata[local_index + 12: local_index + 16])[0],
			}

			if self.loc_information['location_info']['r_drive_type'] < len(self.DRIVE_TYPES):
				self.loc_information['location_info']['drive_type'] = self.DRIVE_TYPES[self.loc_information['location_info']['r_drive_type']]

			if self.loc_information['location_info']['volume_label_offset'] != 20:
				length = self.loc_information['location_info']['volume_id_size'] - self.loc_information['location_info']['volume_label_offset']
				local_index = index + self.loc_information['volume_id_offset'] + self.loc_information['location_info']['volume_label_offset']
				self.loc_information['location_info']['volume_label'] = self.clean_line(self.indata[local_index: local_index + length].replace(b'\x00', b''))
			else:
				self.loc_information['location_info']['o_volume_label_offset_unicode'] = struct.unpack('<i', self.indata[local_index + 16: local_index + 20])[0]
				local_index = index + self.loc_information['volume_id_offset'] + self.loc_information['location_info']['o_volume_label_offset_unicode']
				self.loc_information['location_info']['o_volume_label_unicode'] = struct.unpack('<i', self.indata[local_index: local_index + 4])[0]

		elif self.loc_information['link_info_flags'] & 0x0002:
			"""
			--------------------------------------------------------------------------------------------------
			|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
			--------------------------------------------------------------------------------------------------
			|                           <u_int32> CommonNetworkRelativeLinkSize                              |
			--------------------------------------------------------------------------------------------------
			|                           <flags> CommonNetworkRelativeLinkFlags                               |
			--------------------------------------------------------------------------------------------------
			|                                   <u_int32> NetNameOffset                                      |
			--------------------------------------------------------------------------------------------------
			|                                  <u_int32> DeviceNameOffset                                    |
			--------------------------------------------------------------------------------------------------
			|                                <u_int32> NetworkProviderType                                   |
			--------------------------------------------------------------------------------------------------
			|                          <u_int32> NetNameOffsetUnicode (optional)                             |
			--------------------------------------------------------------------------------------------------
			|                         <u_int32> DeviceNameOffsetUnicode (optional)                           |
			--------------------------------------------------------------------------------------------------
			|                                       <str> NetName                                            |
			|                                            ? B                                                 |
			--------------------------------------------------------------------------------------------------
			|                                     <str> DeviceName                                           |
			|                                            ? B                                                 |
			--------------------------------------------------------------------------------------------------
			|                          <unicode_str> NetNameUnicode (optional)                               |
			|                                            ? B                                                 |
			--------------------------------------------------------------------------------------------------
			|                         <unicode_str> DeviceNameUnicode (optional)                             |
			|                                            ? B                                                 |
			--------------------------------------------------------------------------------------------------
			"""
			if self.loc_information['link_info_header_size'] >= 36:
				self.loc_information['o_common_path_suffix_offset_unicode'] = \
						struct.unpack('<i', self.indata[index + 28: index + 32])[0]
				local_index = index + self.loc_information['o_common_path_suffix_offset_unicode']
				self.loc_information['o_common_path_suffix_unicode'] = struct.unpack('<i', self.indata[local_index: local_index + 4])[0]
			else:
				local_index = index + self.loc_information['common_path_suffix_offset']
				self.loc_information['common_path_suffix'] = \
						struct.unpack('<i', self.indata[local_index: local_index + 4])[0]

			local_index = index + self.loc_information['common_network_relative_link_offset']
			self.loc_information['location'] = 'Network'
			self.loc_information['location_info'] = {
				'common_network_relative_link_size':
					struct.unpack('<i', self.indata[local_index + 0: local_index + 4])[0],
				'common_retwork_relative_link_flags':
					struct.unpack('<i', self.indata[local_index + 4: local_index + 8])[0],
				'net_name_offset':
					struct.unpack('<i', self.indata[local_index + 8: local_index + 12])[0],
				'device_name_offset':
					struct.unpack('<i', self.indata[local_index + 12: local_index + 16])[0],
				'network_provider_type':
					struct.unpack('<i', self.indata[local_index + 16: local_index + 20])[0],
			}

			if self.loc_information['location_info']['o_net_name_offset'] > 20:
				self.loc_information['location_info']['o_net_name_offset_unicode'] = \
				struct.unpack('<i', self.indata[local_index + 20: index + 24])[0]
				local_index = index + self.loc_information['location_info']['o_net_name_offset_unicode']
				self.loc_information['location_info']['o_net_name_offset_unicode'] = \
					struct.unpack('<i', self.indata[local_index: local_index + 4])[0]

				self.loc_information['location_info']['o_device_name_offset_unicode'] = \
				struct.unpack('<i', self.indata[local_index + 24: index + 28])[0]
				local_index = self.loc_information['location_info']['o_device_name_offset_unicode']
				self.loc_information['location_info']['o_device_name_offset_unicode'] = \
					struct.unpack('<i', self.indata[local_index: local_index + 4])[0]
			else:
				local_index = index + self.loc_information['location_info']['o_net_name_offset']
				self.loc_information['location_info']['o_net_name_offset'] = \
					struct.unpack('<i', self.indata[local_index: local_index + 4])[0]

				local_index = self.loc_information['location_info']['o_device_name_offset']
				self.loc_information['location_info']['o_device_name_offset'] = \
					struct.unpack('<i', self.indata[local_index: local_index + 4])[0]


	# Still in development // repair
# 	def parse_targets(self, index):
# 		max_size = self.targets['size'] + index

# 		while ( index  < max_size ):
# 			ItemID = {
# 				"size": struct.unpack('<H', self.indata[index : index + 2])[0] ,
# 				"type": struct.unpack('<B', self.indata[index + 2 : index + 3])[0] ,
# 					}
# 			index += 3

# #			self.targets['items'].append( self.indata[index: index + ItemID['size']].replace('\x00','') )
# #			print "[%s] %s" % (ItemID['size'], hex(ItemID['type']) )#, self.indata[index: index + ItemID['size']].replace('\x00','') )
# #			print self.indata[ index: index + ItemID['size'] ].encode('hex')[:50]
# 			index += ItemID['size']
# #			print self.indata[index + 2: index + 2 + ItemID['size']].replace('\x00','')

	# Still in development // repair
	def parse_targets(self, index):
		return
		max_size = self.targets['size'] + index - 2

		while (index < max_size):
			size = struct.unpack('<H', self.indata[index: index + 2])[0]
			if size:
				print('index1: ' + hex(index + 2))
				print('size: ' + str(size - 2))
				item_type = struct.unpack('<B', self.indata[index + 2 : index + 3])[0]
				print('type' + str(item_type))
				item = self.clean_line(self.indata[index + 3: index + size].replace(b'\x00', b''))
				print('item: ' + item)
				# i = 2
				# while i < size:
				# 	print(chr(self.indata[index + i]))
				# 	i += 1
				self.targets['items'].append(item)
				index += size
				print('index2: ' + hex(index))
				print()
			#           self.targets['items'].append( self.indata[index: index + ItemID['size']].replace('\x00','') )
			#           print('[%s] %s' % (ItemID['size'], hex(ItemID['type']) )#, self.indata[index: index + ItemID['size']].replace('\x00','') ))
			#           print(self.indata[ index: index + ItemID['size'] ].hex()[:50])
			#           print(self.indata[index + 2: index + 2 + ItemID['size']].replace('\x00',''))
		# print(self.targets)


	def parse_string_data(self, index):
		u_mult = 1
		if self.linkFlag['IsUnicode']:
			u_mult = 2

		if self.linkFlag['HasName']:
			index, self.data['description'] = self.read_stringData(index, u_mult)

		if self.linkFlag['HasRelativePath']:
			index, self.data['relative_path'] = self.read_stringData(index, u_mult)

		if self.linkFlag['HasWorkingDir']:
			index, self.data['working_directory'] = self.read_stringData(index, u_mult)

		if self.linkFlag['HasArguments']:
			index, self.data['command_line_arguments'] = self.read_stringData(index, u_mult)

		if self.linkFlag['HasIconLocation']:
			index, self.data['icon_location'] = self.read_stringData(index, u_mult)

		return index


	def process(self):
		index = 0

		# Parse header
		if not self.parse_lnk_header():
			print('Failed Header Check')
		self.parse_link_flags()
		self.parse_file_flags()
		index += self.lnk_header['header_size']

		# Parse ID List
		if self.linkFlag['HasTargetIDList']:
			try:
				self.targets['size'] = struct.unpack('<H', self.indata[index: index + 2])[0]
				index += 2
				if self.debug:
					self.parse_targets(index)
				index += self.targets['size']
			except Exception as e:
				if self.debug:
					print('Exception parsing TargetIDList: %s' % e)
				return False

		# Parse Link Info
		if self.linkFlag['HasLinkInfo'] and self.linkFlag['ForceNoLinkInfo'] == False:
			try:
				self.parse_link_information(index)
				index += (self.loc_information['link_info_size'])
			except Exception as e:
				if self.debug:
					print('Exception parsing Location information: %s' % e)
				return False

		# Parse String Data
		try:
			index = self.parse_string_data(index)
		except Exception as e:
			if self.debug:
				print('Exception in parsing data: %s' % e)
			return False

		# Parse Extra Data
		try:
			while index <= len(self.indata) - 10:
				try:
					size = struct.unpack('<I', self.indata[index: index + 4])[0]
					sig = str(hex(struct.unpack('<I', self.indata[index + 4: index + 8])[0]))[2:]
					self.EXTRA_SIGS[sig](index, size)

					index += (size)
				except Exception as e:
					if self.debug:
						print('Exception in EXTRABLOCK Parsing: %s ' % e)
					index = len(self.data)
					break
		except Exception as e:
			if self.debug:
				print('Exception in EXTRABLOCK: %s' % e)


	def parse_environment_block(self, index, size):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> BlockSize == 0x00000314                                 |
		--------------------------------------------------------------------------------------------------
		|                            <u_int32> BlockSignature == 0xA0000001                              |
		--------------------------------------------------------------------------------------------------
		|                                      <str> TargetAnsi                                          |
		|                                           260 B                                                |
		--------------------------------------------------------------------------------------------------
		|                                <unicode_str> TargetUnicode                                     |
		|                                           520 B                                                |
		--------------------------------------------------------------------------------------------------
		"""
		self.extraBlocks['ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK'] = {}
		self.extraBlocks['ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK']['size'] = size
		self.extraBlocks['ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK']['TargetAnsi'] = self.read_string(index + 8)
		self.extraBlocks['ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK']['TargetUnicode'] = self.read_unicode_string(index + 268)


	def parse_console_block(self, index, size):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> BlockSize == 0x000000CC                                 |
		--------------------------------------------------------------------------------------------------
		|                            <u_int32> BlockSignature == 0xA0000002                              |
		--------------------------------------------------------------------------------------------------
		|         <u_int16> FillAttributes             |        <u_int16> PopupFillAttributes            |
		--------------------------------------------------------------------------------------------------
		|         <int16> ScreenBufferSizeX            |             <int16> ScreenBufferSizeY           |
		|             <int16> WindowSizeX              |               <int16> WindowSizeY               |
		--------------------------------------------------------------------------------------------------
		|            <int16> WindowOriginX             |              <int16> WindowOriginY              |
		--------------------------------------------------------------------------------------------------
		|                                           Unused1                                              |
		--------------------------------------------------------------------------------------------------
		|                                           Unused2                                              |
		--------------------------------------------------------------------------------------------------
		|                                      <u_int32> FontSize                                        |
		--------------------------------------------------------------------------------------------------
		|                                     <u_int32> FontFamily                                       |
		--------------------------------------------------------------------------------------------------
		|                                     <u_int32> FontWeight                                       |
		--------------------------------------------------------------------------------------------------
		|                                    <unicode_str> Face Name                                     |
		|                                            64 B                                                |
		--------------------------------------------------------------------------------------------------
		|                                     <u_int32> CursorSize                                       |
		--------------------------------------------------------------------------------------------------
		|                                     <u_int32> FullScreen                                       |
		--------------------------------------------------------------------------------------------------
		|                                      <u_int32> QuickEdit                                       |
		--------------------------------------------------------------------------------------------------
		|                                     <u_int32> InsertMode                                       |
		--------------------------------------------------------------------------------------------------
		|                                    <u_int32> AutoPosition                                      |
		--------------------------------------------------------------------------------------------------
		|                                 <u_int32> HistoryBufferSize                                    |
		--------------------------------------------------------------------------------------------------
		|                               <u_int32> NumberOfHistoryBuffers                                 |
		--------------------------------------------------------------------------------------------------
		|                                   <u_int32> HistoryNoDup                                       |
		--------------------------------------------------------------------------------------------------
		|                                <vector<u_int32>> ColorTable                                    |
		|                                            64 B                                                |
		--------------------------------------------------------------------------------------------------
		"""
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'] = {}
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK']['size'] = size
		# 16b
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'fill_attributes'] = struct.unpack('<I', self.indata[index + 8: index + 10])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'popup_fill_attributes'] = struct.unpack('<I', self.indata[index + 10: index + 12])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'screen_buffer_size_x'] = struct.unpack('<i', self.indata[index + 12: index + 14])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'screen_buffer_size_y'] = struct.unpack('<i', self.indata[index + 14: index + 16])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'window_size_x'] = struct.unpack('<i', self.indata[index + 16: index + 18])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'window_size_y'] = struct.unpack('<i', self.indata[index + 18: index + 20])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'window_origin_x'] = struct.unpack('<i', self.indata[index + 20: index + 22])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'window_origin_y'] = struct.unpack('<i', self.indata[index + 22: index + 24])[0]
		# Bytes 24-28 & 28-32 are unused
		# 32b
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'font_size'] = struct.unpack('<I', self.indata[index + 32: index + 36])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'font_family'] = struct.unpack('<I', self.indata[index + 36: index + 40])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'font_weight'] = struct.unpack('<I', self.indata[index + 40: index + 44])[0]
		# 64b
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'face_name'] = self.clean_line(self.indata[index + 44: index + 108])
		# 32b
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'cursor_size'] = struct.unpack('<I', self.indata[index + 108: index + 112])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'full_screen'] = struct.unpack('<I', self.indata[index + 112: index + 116])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'quick_edit'] = struct.unpack('<I', self.indata[index + 116: index + 120])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'insert_mode'] = struct.unpack('<I', self.indata[index + 120: index + 124])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'auto_position'] = struct.unpack('<I', self.indata[index + 124: index + 128])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'history_buffer_size'] = struct.unpack('<I', self.indata[index + 128: index + 132])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'number_of_history_buffers'] = struct.unpack('<I', self.indata[index + 132: index + 136])[0]
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'history_no_dup'] = struct.unpack('<I', self.indata[index + 136: index + 140])[0]
		# 64b
		self.extraBlocks['CONSOLE_PROPERTIES_BLOCK'][
			'color_table'] = struct.unpack('<I', self.indata[index + 140: index + 144])[0]


	def parse_distributedTracker_block(self, index, size):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> BlockSize == 0x00000060                                 |
		--------------------------------------------------------------------------------------------------
		|                            <u_int32> BlockSignature == 0xA0000003                              |
		--------------------------------------------------------------------------------------------------
		|                                      <u_int32> Length                                          |
		--------------------------------------------------------------------------------------------------
		|                                      <u_int32> Version                                         |
		--------------------------------------------------------------------------------------------------
		|                                       <str> MachineID                                          |
		|                                             16 B                                               |
		--------------------------------------------------------------------------------------------------
		|                                    <GUID> DroidVolumeId                                        |
		|                                             16 B                                               |
		--------------------------------------------------------------------------------------------------
		|                                     <GUID> DroidFileId                                         |
		|                                             16 B                                               |
		--------------------------------------------------------------------------------------------------
		|                                  <GUID> DroidBirthVolumeId                                     |
		|                                             16 B                                               |
		--------------------------------------------------------------------------------------------------
		|                                   <GUID> DroidBirthFileId                                      |
		|                                             16 B                                               |
		--------------------------------------------------------------------------------------------------
		"""
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK'] = {}
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK']['size'] = size
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK']['length'] = \
			struct.unpack('<I', self.indata[index + 8: index + 12])[0]
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK']['version'] = \
			struct.unpack('<I', self.indata[index + 12: index + 16])[0]
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK'][
			'machine_identifier'] = self.clean_line(self.indata[index + 16: index + 32])
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK'][
			'droid_volume_identifier'] = self.indata[index + 32: index + 48].hex()
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK'][
			'droid_file_identifier'] = self.indata[index + 48: index + 64].hex()
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK'][
			'birth_droid_volume_identifier'] = self.indata[index + 64: index + 80].hex()
		self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK'][
			'birth_droid_file_identifier'] = self.indata[index + 80: index + 96].hex()


	def parse_codepage_block(self, index, size):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> BlockSize == 0x0000000C                                 |
		--------------------------------------------------------------------------------------------------
		|                            <u_int32> BlockSignature == 0xA0000004                              |
		--------------------------------------------------------------------------------------------------
		|                                     <u_int32> CodePage                                         |
		--------------------------------------------------------------------------------------------------
		"""
		self.extraBlocks['CONSOLE_CODEPAGE_BLOCK'] = {}
		self.extraBlocks['CONSOLE_CODEPAGE_BLOCK']['size'] = size
		self.extraBlocks['CONSOLE_CODEPAGE_BLOCK']['code_page'] = struct.unpack('<I', self.indata[index + 8: index + 12])[0]


	def parse_specialFolder_block(self, index, size):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> BlockSize == 0x00000010                                 |
		--------------------------------------------------------------------------------------------------
		|                            <u_int32> BlockSignature == 0xA0000005                              |
		--------------------------------------------------------------------------------------------------
		|                                   <u_int32> SpecialFolderID                                    |
		--------------------------------------------------------------------------------------------------
		|                                         <u_int32> Offset                                       |
		--------------------------------------------------------------------------------------------------
		"""
		self.extraBlocks['SPECIAL_FOLDER_LOCATION_BLOCK'] = {}
		self.extraBlocks['SPECIAL_FOLDER_LOCATION_BLOCK']['size'] = size
		self.extraBlocks['SPECIAL_FOLDER_LOCATION_BLOCK']['special_folder_id'] = struct.unpack('<I', self.indata[index + 8: index + 12])[0]
		self.extraBlocks['SPECIAL_FOLDER_LOCATION_BLOCK']['offset'] = struct.unpack('<I', self.indata[index + 12: index + 16])[0]


	def parse_darwin_block(self, index, size):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> BlockSize == 0x00000314                                 |
		--------------------------------------------------------------------------------------------------
		|                            <u_int32> BlockSignature == 0xA0000006                              |
		--------------------------------------------------------------------------------------------------
		|                                    <str> DarwinDataAnsi                                        |
		|                                           260 B                                                |
		--------------------------------------------------------------------------------------------------
		|                               <unicode_str> DarwinDataUnicode                                  |
		|                                           520 B                                                |
		--------------------------------------------------------------------------------------------------
		"""
		self.extraBlocks['DARWIN_BLOCK'] = {}
		self.extraBlocks['DARWIN_BLOCK']['size'] = size
		self.extraBlocks['DARWIN_BLOCK']['darwin_data_ansi'] = self.read_string(index + 8)
		self.extraBlocks['DARWIN_BLOCK']['darwin_data_unicode'] = self.read_unicode_string(index + 268)


	def parse_icon_block(self, index, size):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> BlockSize == 0x00000314                                 |
		--------------------------------------------------------------------------------------------------
		|                            <u_int32> BlockSignature == 0xA0000007                              |
		--------------------------------------------------------------------------------------------------
		|                                      <str> TargetAnsi                                          |
		|                                           260 B                                                |
		--------------------------------------------------------------------------------------------------
		|                                <unicode_str> TargetUnicode                                     |
		|                                           520 B                                                |
		--------------------------------------------------------------------------------------------------
		"""
		self.extraBlocks['ICON_LOCATION_BLOCK'] = {}
		self.extraBlocks['ICON_LOCATION_BLOCK']['size'] = size
		self.extraBlocks['ICON_LOCATION_BLOCK']['target_ansi'] = self.read_string(index + 8)
		self.extraBlocks['ICON_LOCATION_BLOCK']['target_unicode'] = self.read_unicode_string(index + 268)


	def parse_shimLayer_block(self, index, size):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> BlockSize >= 0x00000088                                 |
		--------------------------------------------------------------------------------------------------
		|                            <u_int32> BlockSignature == 0xA0000008                              |
		--------------------------------------------------------------------------------------------------
		|                                    <unicode_str> LayerName                                     |
		|                                            ? B                                                 |
		--------------------------------------------------------------------------------------------------
		"""
		self.extraBlocks['SHIM_LAYER_BLOCK'] = {}
		self.extraBlocks['SHIM_LAYER_BLOCK']['size'] = size
		self.extraBlocks['SHIM_LAYER_BLOCK']['layer_name'] = self.read_unicode_string(index + 8)


	def parse_metadata_block(self, index, size):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> BlockSize >= 0x0000000C                                 |
		--------------------------------------------------------------------------------------------------
		|                            <u_int32> BlockSignature == 0xA0000009                              |
		--------------------------------------------------------------------------------------------------
		|                                    <u_int32> StorageSize                                       |
		--------------------------------------------------------------------------------------------------
		|                                    Version == 0x53505331                                       |
		--------------------------------------------------------------------------------------------------
		|                                      <GUID> FormatID                                           |
		|                                            16 B                                                |
		--------------------------------------------------------------------------------------------------
		|                   <vector<MS_OLEPS>> SerializedPropertyValue (see MS-OLEPS)                    |
		|                                             ? B                                                |
		--------------------------------------------------------------------------------------------------
		"""
		self.extraBlocks['METADATA_PRPERTIES_BLOCK'] = {}
		self.extraBlocks['METADATA_PRPERTIES_BLOCK']['size'] = size
		self.extraBlocks['METADATA_PRPERTIES_BLOCK']['storage_size'] = struct.unpack('<I', self.indata[index + 8: index + 12])[0]
		self.extraBlocks['METADATA_PRPERTIES_BLOCK']['version'] = hex(struct.unpack('<I', self.indata[index + 12: index + 16])[0])
		self.extraBlocks['METADATA_PRPERTIES_BLOCK']['format_id'] = self.indata[index + 16: index + 32].hex()
		if self.extraBlocks['METADATA_PRPERTIES_BLOCK']['format_id'].upper() == 'D5CDD5052E9C101B939708002B2CF9AE':
			# Serialized Property Value (String Name)
			index += 32
			result = []
			while True:
				value = {}
				value['value_size'] = struct.unpack('<I', self.indata[index: index + 4])[0]
				if hex(value['value_size']) == hex(0x0):
					break
				value['name_size'] = struct.unpack('<I', self.indata[index + 4: index + 8])[0]
				value['name'] = self.read_unicode_string(index + 8)
				value['value'] = '' # TODO MS-OLEPS

				result.append(value)
				index += 4 + 4 + 2 + value['name_size'] + value['value_size']

			self.extraBlocks['METADATA_PRPERTIES_BLOCK']['serialized_property_value_string'] = result
		else:
			# Serialized Property Value (Integer Name)
			try:
				index += 32
				result = []
				while True:
					value = {}
					value['value_size'] = struct.unpack('<I', self.indata[index: index + 4])[0]
					if hex(value['value_size']) == hex(0x0):
						break
					value['id'] = struct.unpack('<I', self.indata[index + 4: index + 8])[0]
					value['value'] = '' # TODO MS-OLEPS

					result.append(value)
					index += value['value_size']

				self.extraBlocks['METADATA_PRPERTIES_BLOCK']['serialized_property_value_integer'] = result
			except Exception as e:
				print(e)


	def parse_knownFolder_block(self, index, size):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> BlockSize == 0x0000001C                                 |
		--------------------------------------------------------------------------------------------------
		|                            <u_int32> BlockSignature == 0xA000000B                              |
		--------------------------------------------------------------------------------------------------
		|                                     <GUID> KnownFolderID                                       |
		|                                            16 B                                                |
		--------------------------------------------------------------------------------------------------
		|                                       <u_int32> Offset                                         |
		--------------------------------------------------------------------------------------------------
		"""
		self.extraBlocks['KNOWN_FOLDER_LOCATION_BLOCK'] = {}
		self.extraBlocks['KNOWN_FOLDER_LOCATION_BLOCK']['size'] = size
		self.extraBlocks['KNOWN_FOLDER_LOCATION_BLOCK']['known_folder_id'] = self.indata[index + 8: index + 24].hex()
		self.extraBlocks['KNOWN_FOLDER_LOCATION_BLOCK']['offset'] = struct.unpack('<I', self.indata[index + 24: index + 28])[0]


	def parse_shellItem_block(self, index, size):
		"""
		--------------------------------------------------------------------------------------------------
		|         0-7b         |         8-15b         |         16-23b         |         24-31b         |
		--------------------------------------------------------------------------------------------------
		|                              <u_int32> BlockSize >= 0x0000000A                                 |
		--------------------------------------------------------------------------------------------------
		|                            <u_int32> BlockSignature == 0xA000000C                              |
		--------------------------------------------------------------------------------------------------
		|                                       <IDList> IDList                                          |
		--------------------------------------------------------------------------------------------------
		"""
		self.extraBlocks['SHELL_ITEM_IDENTIFIER_BLOCK'] = {}
		self.extraBlocks['SHELL_ITEM_IDENTIFIER_BLOCK']['size'] = size
		self.extraBlocks['SHELL_ITEM_IDENTIFIER_BLOCK']['id_list'] = '' # TODO


	def print_lnk_file(self):
		print('Windows Shortcut Information:')
		print('\tLink Flags: %s - (%s)' % (self.format_linkFlags(), self.lnk_header['r_link_flags']))
		print('\tFile Flags: %s - (%s)' % (self.format_fileFlags(), self.lnk_header['r_file_flags']))
		print('')
		try:
			print('\tCreation Timestamp: %s' % (self.ms_time_to_unix_time(self.lnk_header['creation_time'])))
			print('\tModified Timestamp: %s' % (self.ms_time_to_unix_time(self.lnk_header['modified_time'])))
			print('\tAccessed Timestamp: %s' % (self.ms_time_to_unix_time(self.lnk_header['accessed_time'])))
			print('')
		except:
			print('\tProblem Parsing Timestamps')
		print(
			'\tFile Size: %s (r: %s)' % (str(self.lnk_header['file_size']), str(len(self.indata))))
		print('\tIcon Index: %s ' % (str(self.lnk_header['icon_index'])))
		print('\tWindow Style: %s ' % (str(self.lnk_header['windowstyle'])))
		print('\tHotKey: %s ' % (str(self.lnk_header['hotkey'])))

		print('')

		for rline in self.data:
			print('\t%s: %s' % (rline, self.data[rline]))

		print('')
		print('\tEXTRA BLOCKS:')
		for enabled in self.extraBlocks:
			print('\t\t%s' % enabled)
			for block in self.extraBlocks[enabled]:
				print('\t\t\t[%s] %s' % (block, self.extraBlocks[enabled][block]))


	@staticmethod
	def ms_time_to_unix_time(time):
		if time == 0:
			return ''
		return datetime.datetime.fromtimestamp(time / 10000000.0 - 11644473600).strftime('%Y-%m-%d %H:%M:%S')


	def read_string(self, index):
		result = ''
		while self.indata[index] != 0x00:
			result += chr(self.indata[index])
			index += 1
		return result


	def read_unicode_string(self, index):
		begin = end = index
		while self.indata[index] != 0x00:
			end += 1
			index += 1
		return self.clean_line(self.indata[begin: end].replace(b'\x00', b''))


	def read_stringData(self, index, u_mult):
		string_size = struct.unpack('<H', self.indata[index: index + 2])[0] * u_mult
		string = self.clean_line(self.indata[index + 2: index + 2 + string_size].replace(b'\x00', b''))
		new_index = index + string_size + 2
		return new_index, string


	@staticmethod
	def enabled_flags_to_list(flags):
		enabled = []
		for flag in flags:
			if flags[flag]:
				enabled.append(flag)
		return enabled


	def format_linkFlags(self):
		enabled = self.enabled_flags_to_list(self.linkFlag)
		return ' | '.join(enabled)


	def format_fileFlags(self):
		enabled = self.enabled_flags_to_list(self.fileFlag)
		return ' | '.join(enabled)


	def print_short(self, pjson=False):
		out = ''
		if self.linkFlag['HasRelativePath']:
			out += self.data['relative_path']
		if self.linkFlag['HasArguments']:
			out += ' ' + self.data['command_line_arguments']

		if pjson:
			print(json.dumps({'command': out}))
		else:
			print(out)


	def print_json(self, print_all=False):
		res = self.get_json(print_all)
		print(json.dumps(res, indent=4, separators=(',', ': ')))


	def get_json(self, get_all=False):
		res = {'header': self.lnk_header, 'data': self.data, 'target': self.targets, 'link_info': self.loc_information, 'extra': self.extraBlocks}

		if 'creation_time' in res['header']:
			res['header']['creation_time'] = self.ms_time_to_unix_time(res['header']['creation_time'])
		if 'accessed_time' in res['header']:
			res['header']['accessed_time'] = self.ms_time_to_unix_time(res['header']['accessed_time'])
		if 'modified_time' in res['header']:
			res['header']['modified_time'] = self.ms_time_to_unix_time(res['header']['modified_time'])

		if not get_all:
			res['header'].pop('header_size', None)
			res['header'].pop('reserved0', None)
			res['header'].pop('reserved1', None)
			res['header'].pop('reserved2', None)
			res['target'].pop('size', None)
			res['link_info'].pop('link_info_size', None)
			res['link_info'].pop('link_info_header_size', None)
			res['link_info'].pop('volume_id_offset', None)
			res['link_info'].pop('local_base_path_offset', None)
			res['link_info'].pop('common_network_relative_link_offset', None)
			res['link_info'].pop('common_path_suffix_offset', None)
			if 'Local' in res['link_info']:
				res['link_info']['location_info'].pop('volume_id_size', None)
				res['link_info']['location_info'].pop('volume_label_offset', None)
			if 'Network' in res['link_info']:
				res['link_info']['location_info'].pop('common_network_relative_link_size', None)
				res['link_info']['location_info'].pop('net_name_offset', None)
				res['link_info']['location_info'].pop('device_name_offset', None)

		return res


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
		lnk = lnk_file(fhandle=file, debug=args.debug)
		if args.json:
			lnk.print_json(args.json_debug)
		else:
			lnk.print_lnk_file()


if __name__ == '__main__':
	main()
