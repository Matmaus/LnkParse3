#!/usr/bin/env python3

__description__ = "Windows Shortcut file (LNK) parser"
__author__ = "Matúš Jasnický"
__version__ = "0.3.3"

import json
import struct
import datetime
import argparse

from LnkParse3.lnk_header import lnk_header
from LnkParse3.lnk_targets import lnk_targets
from LnkParse3.lnk_info import lnk_info
from LnkParse3.info_factory import info_factory
from LnkParse3.string_data import string_data


class lnk_file(object):
    def __init__(self, fhandle=None, indata=None, debug=False):
        self.define_static()

        if fhandle:
            self.indata = fhandle.read()
        elif indata:
            self.indata = indata

        self.debug = debug

        self.data = {}
        self.extraBlocks = {}

        self.process()
        self.define_common()

    def has_relative_path(self):
        return bool("HasRelativePath" in self.header.link_flags())

    def has_arguments(self):
        return bool("HasArguments" in self.header.link_flags())

    def is_unicode(self):
        return bool("IsUnicode" in self.header.link_flags())

    def has_name(self):
        return bool("HasName" in self.header.link_flags())

    def has_working_dir(self):
        return bool("HasWorkingDir" in self.header.link_flags())

    def has_icon_location(self):
        return bool("HasIconLocation" in self.header.link_flags())

    def has_target_id_list(self):
        return bool("HasTargetIDList" in self.header.link_flags())

    def has_link_info(self):
        return bool("HasLinkInfo" in self.header.link_flags())

    def force_no_link_info(self):
        return bool("ForceNoLinkInfo" in self.header.link_flags())

    def define_common(self):
        try:
            out = ""
            if self.has_relative_path():
                out += self.data["relative_path"]
            if self.has_arguments():
                out += " " + self.data["command_line_arguments"]

            self.lnk_command = out
        except Exception as e:
            if self.debug:
                print("Exception define_common: %s" % e)

    def get_command(self):
        try:
            out = ""
            if self.has_relative_path():
                out += self.data["relative_path"]
            if self.has_arguments():
                out += " " + self.data["command_line_arguments"]

            return out
        except Exception as e:
            if self.debug:
                print("Exception get_command: %s" % (e))
            return ""

    def define_static(self):
        # Define static constents used within the LNK format

        # Each MAGIC string refernces a function for processing
        self.EXTRA_SIGS = {
            "a0000001": self.parse_environment_block,
            "a0000002": self.parse_console_block,
            "a0000003": self.parse_distributedTracker_block,
            "a0000004": self.parse_codepage_block,
            "a0000005": self.parse_specialFolder_block,
            "a0000006": self.parse_darwin_block,
            "a0000007": self.parse_icon_block,
            "a0000008": self.parse_shimLayer_block,
            "a0000009": self.parse_metadata_block,
            "a000000b": self.parse_knownFolder_block,
            "a000000c": self.parse_shellItem_block,
        }

    @staticmethod
    def clean_line(rstring):
        return "".join(chr(i) for i in rstring if 128 > i > 20)

    def process(self):
        index = 0

        # Parse header
        self.header = lnk_header(indata=self.indata)
        index += self.header.size()

        # XXX: json
        self._target_index = index + 2

        # Parse ID List
        self.targets = None
        if self.has_target_id_list():
            self.targets = lnk_targets(indata=self.indata[index:])
            index += self.targets.size()

        # Parse Link Info
        self.info = None
        if self.has_link_info() and not self.force_no_link_info():
            info = lnk_info(indata=self.indata[index:])
            info_class = info_factory(info).info_class()
            if info_class:
                self.info = info_class(indata=self.indata[index:])
                index += self.info.size()

        # Parse String Data
        self.string_data = string_data(self, indata=self.indata[index:])
        index += self.string_data.size()

        # Parse Extra Data
        try:
            while index <= len(self.indata) - 10:
                try:
                    size = struct.unpack("<I", self.indata[index : index + 4])[0]
                    sig = str(
                        hex(struct.unpack("<I", self.indata[index + 4 : index + 8])[0])
                    )[2:]
                    self.EXTRA_SIGS[sig](index, size)

                    index += size
                    if size == 0:
                        break
                except Exception as e:
                    if self.debug:
                        print("Exception in EXTRABLOCK Parsing: %s " % e)
                    index = len(self.data)
                    break
        except Exception as e:
            if self.debug:
                print("Exception in EXTRABLOCK: %s" % e)

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
        self.extraBlocks["ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK"] = {}
        self.extraBlocks["ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK"]["size"] = size
        self.extraBlocks["ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK"][
            "target_ansi"
        ] = self.read_string(index + 8)
        self.extraBlocks["ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK"][
            "target_unicode"
        ] = self.read_unicode_string(index + 268)

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
        --------------------------------------------------------------------------------------------------
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
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"] = {}
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["size"] = size
        # 16b
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["fill_attributes"] = struct.unpack(
            "<I", self.indata[index + 8 : index + 10]
        )[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"][
            "popup_fill_attributes"
        ] = struct.unpack("<I", self.indata[index + 10 : index + 12])[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"][
            "screen_buffer_size_x"
        ] = struct.unpack("<i", self.indata[index + 12 : index + 14])[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"][
            "screen_buffer_size_y"
        ] = struct.unpack("<i", self.indata[index + 14 : index + 16])[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["window_size_x"] = struct.unpack(
            "<i", self.indata[index + 16 : index + 18]
        )[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["window_size_y"] = struct.unpack(
            "<i", self.indata[index + 18 : index + 20]
        )[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["window_origin_x"] = struct.unpack(
            "<i", self.indata[index + 20 : index + 22]
        )[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["window_origin_y"] = struct.unpack(
            "<i", self.indata[index + 22 : index + 24]
        )[0]
        # Bytes 24-28 & 28-32 are unused
        # 32b
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["font_size"] = struct.unpack(
            "<I", self.indata[index + 32 : index + 36]
        )[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["font_family"] = struct.unpack(
            "<I", self.indata[index + 36 : index + 40]
        )[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["font_weight"] = struct.unpack(
            "<I", self.indata[index + 40 : index + 44]
        )[0]
        # 64b
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["face_name"] = self.clean_line(
            self.indata[index + 44 : index + 108]
        )
        # 32b
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["cursor_size"] = struct.unpack(
            "<I", self.indata[index + 108 : index + 112]
        )[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["full_screen"] = struct.unpack(
            "<I", self.indata[index + 112 : index + 116]
        )[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["quick_edit"] = struct.unpack(
            "<I", self.indata[index + 116 : index + 120]
        )[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["insert_mode"] = struct.unpack(
            "<I", self.indata[index + 120 : index + 124]
        )[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["auto_position"] = struct.unpack(
            "<I", self.indata[index + 124 : index + 128]
        )[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"][
            "history_buffer_size"
        ] = struct.unpack("<I", self.indata[index + 128 : index + 132])[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"][
            "number_of_history_buffers"
        ] = struct.unpack("<I", self.indata[index + 132 : index + 136])[0]
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["history_no_dup"] = struct.unpack(
            "<I", self.indata[index + 136 : index + 140]
        )[0]
        # 64b
        self.extraBlocks["CONSOLE_PROPERTIES_BLOCK"]["color_table"] = struct.unpack(
            "<I", self.indata[index + 140 : index + 144]
        )[0]

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
        self.extraBlocks["DISTRIBUTED_LINK_TRACKER_BLOCK"] = {}
        self.extraBlocks["DISTRIBUTED_LINK_TRACKER_BLOCK"]["size"] = size
        self.extraBlocks["DISTRIBUTED_LINK_TRACKER_BLOCK"]["length"] = struct.unpack(
            "<I", self.indata[index + 8 : index + 12]
        )[0]
        self.extraBlocks["DISTRIBUTED_LINK_TRACKER_BLOCK"]["version"] = struct.unpack(
            "<I", self.indata[index + 12 : index + 16]
        )[0]
        self.extraBlocks["DISTRIBUTED_LINK_TRACKER_BLOCK"][
            "machine_identifier"
        ] = self.read_string(index + 16)
        self.extraBlocks["DISTRIBUTED_LINK_TRACKER_BLOCK"][
            "droid_volume_identifier"
        ] = self.indata[index + 32 : index + 48].hex()
        self.extraBlocks["DISTRIBUTED_LINK_TRACKER_BLOCK"][
            "droid_file_identifier"
        ] = self.indata[index + 48 : index + 64].hex()
        self.extraBlocks["DISTRIBUTED_LINK_TRACKER_BLOCK"][
            "birth_droid_volume_identifier"
        ] = self.indata[index + 64 : index + 80].hex()
        self.extraBlocks["DISTRIBUTED_LINK_TRACKER_BLOCK"][
            "birth_droid_file_identifier"
        ] = self.indata[index + 80 : index + 96].hex()

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
        self.extraBlocks["CONSOLE_CODEPAGE_BLOCK"] = {}
        self.extraBlocks["CONSOLE_CODEPAGE_BLOCK"]["size"] = size
        self.extraBlocks["CONSOLE_CODEPAGE_BLOCK"]["code_page"] = struct.unpack(
            "<I", self.indata[index + 8 : index + 12]
        )[0]

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
        self.extraBlocks["SPECIAL_FOLDER_LOCATION_BLOCK"] = {}
        self.extraBlocks["SPECIAL_FOLDER_LOCATION_BLOCK"]["size"] = size
        self.extraBlocks["SPECIAL_FOLDER_LOCATION_BLOCK"][
            "special_folder_id"
        ] = struct.unpack("<I", self.indata[index + 8 : index + 12])[0]
        self.extraBlocks["SPECIAL_FOLDER_LOCATION_BLOCK"]["offset"] = struct.unpack(
            "<I", self.indata[index + 12 : index + 16]
        )[0]

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
        self.extraBlocks["DARWIN_BLOCK"] = {}
        self.extraBlocks["DARWIN_BLOCK"]["size"] = size
        self.extraBlocks["DARWIN_BLOCK"]["darwin_data_ansi"] = self.read_string(
            index + 8
        )
        self.extraBlocks["DARWIN_BLOCK"][
            "darwin_data_unicode"
        ] = self.read_unicode_string(index + 268)

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
        self.extraBlocks["ICON_LOCATION_BLOCK"] = {}
        self.extraBlocks["ICON_LOCATION_BLOCK"]["size"] = size
        self.extraBlocks["ICON_LOCATION_BLOCK"]["target_ansi"] = self.read_string(
            index + 8
        )
        self.extraBlocks["ICON_LOCATION_BLOCK"][
            "target_unicode"
        ] = self.read_unicode_string(index + 268)

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
        self.extraBlocks["SHIM_LAYER_BLOCK"] = {}
        self.extraBlocks["SHIM_LAYER_BLOCK"]["size"] = size
        self.extraBlocks["SHIM_LAYER_BLOCK"]["layer_name"] = self.read_unicode_string(
            index + 8
        )

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
        self.extraBlocks["METADATA_PROPERTIES_BLOCK"] = {}
        self.extraBlocks["METADATA_PROPERTIES_BLOCK"]["size"] = size
        self.extraBlocks["METADATA_PROPERTIES_BLOCK"]["storage_size"] = struct.unpack(
            "<I", self.indata[index + 8 : index + 12]
        )[0]
        self.extraBlocks["METADATA_PROPERTIES_BLOCK"]["version"] = hex(
            struct.unpack("<I", self.indata[index + 12 : index + 16])[0]
        )
        self.extraBlocks["METADATA_PROPERTIES_BLOCK"]["format_id"] = self.indata[
            index + 16 : index + 32
        ].hex()

        if not self.debug:
            return

        if (
            self.extraBlocks["METADATA_PROPERTIES_BLOCK"]["format_id"].upper()
            == "D5CDD5052E9C101B939708002B2CF9AE"
        ):
            # Serialized Property Value (String Name)
            index += 32
            result = []
            while True:
                value = {}
                value["value_size"] = struct.unpack(
                    "<I", self.indata[index : index + 4]
                )[0]
                if hex(value["value_size"]) == hex(0x0):
                    break
                value["name_size"] = struct.unpack(
                    "<I", self.indata[index + 4 : index + 8]
                )[0]
                value["name"] = self.read_unicode_string(index + 8)
                value["value"] = ""  # TODO MS-OLEPS

                result.append(value)
                index += 4 + 4 + 2 + value["name_size"] + value["value_size"]

            self.extraBlocks["METADATA_PROPERTIES_BLOCK"][
                "serialized_property_value_string"
            ] = result
        else:
            # Serialized Property Value (Integer Name)
            try:
                index += 32
                result = []
                while True:
                    value = {}
                    value["value_size"] = struct.unpack(
                        "<I", self.indata[index : index + 4]
                    )[0]
                    if hex(value["value_size"]) == hex(0x0):
                        break
                    value["id"] = struct.unpack(
                        "<I", self.indata[index + 4 : index + 8]
                    )[0]
                    value["value"] = ""  # TODO MS-OLEPS

                    result.append(value)
                    index += value["value_size"]

                self.extraBlocks["METADATA_PROPERTIES_BLOCK"][
                    "serialized_property_value_integer"
                ] = result
            except Exception as e:
                if self.debug:
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
        self.extraBlocks["KNOWN_FOLDER_LOCATION_BLOCK"] = {}
        self.extraBlocks["KNOWN_FOLDER_LOCATION_BLOCK"]["size"] = size
        self.extraBlocks["KNOWN_FOLDER_LOCATION_BLOCK"][
            "known_folder_id"
        ] = self.indata[index + 8 : index + 24].hex()
        self.extraBlocks["KNOWN_FOLDER_LOCATION_BLOCK"]["offset"] = struct.unpack(
            "<I", self.indata[index + 24 : index + 28]
        )[0]

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
        self.extraBlocks["SHELL_ITEM_IDENTIFIER_BLOCK"] = {}
        self.extraBlocks["SHELL_ITEM_IDENTIFIER_BLOCK"]["size"] = size
        self.extraBlocks["SHELL_ITEM_IDENTIFIER_BLOCK"]["id_list"] = ""  # TODO

    def print_lnk_file(self):
        print("Windows Shortcut Information:")
        print(
            "\tLink Flags: %s - (%s)"
            % (self.format_linkFlags(), self.header.r_link_flags())
        )
        print(
            "\tFile Flags: %s - (%s)"
            % (self.format_fileFlags(), self.header.r_file_flags())
        )
        print("")
        print("\tCreation Timestamp: %s" % (self.header.creation_time()))
        print("\tModified Timestamp: %s" % (self.header.write_time()))
        print("\tAccessed Timestamp: %s" % (self.header.access_time()))
        print("")
        print(
            "\tFile Size: %s (r: %s)"
            % (str(self.header.file_size()), str(len(self.indata)))
        )
        print("\tIcon Index: %s " % (str(self.header.icon_index())))
        print("\tWindow Style: %s " % (str(self.header.window_style())))
        print("\tHotKey: %s " % (str(self.header.hot_key())))
        print("")

        for key, value in self.string_data.as_dict().items():
            print("\t%s: %s" % (key, value))

        print("")
        print("\tEXTRA BLOCKS:")
        for enabled in self.extraBlocks:
            print("\t\t%s" % enabled)
            for block in self.extraBlocks[enabled]:
                print("\t\t\t[%s] %s" % (block, self.extraBlocks[enabled][block]))

    @staticmethod
    def dos_time_to_unix_time(time):
        """
         The DOS date/time format is a bitmask:

        24                16                 8                 0
         +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
         |Y|Y|Y|Y|Y|Y|Y|M| |M|M|M|D|D|D|D|D| |h|h|h|h|h|m|m|m| |m|m|m|s|s|s|s|s|
         +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
          \___________/\________/\_________/ \________/\____________/\_________/
             year        month       day      hour       minute        second

         The year is stored as an offset from 1980.
         Seconds are stored in two-second increments.
         (So if the "second" value is 15, it actually represents 30 seconds.)
         Source: https://stackoverflow.com/questions/15763259/unix-timestamp-to-fat-timestamp
         https://docs.microsoft.com/pl-pl/windows/desktop/api/winbase/nf-winbase-dosdatetimetofiletime
         https://github.com/log2timeline/dfdatetime/wiki/Date-and-time-values
        """
        if time == 0:
            return ""
        try:
            ymdhms = (
                ((time & 0xFE000000) >> 25) + 1980,
                ((time & 0x01E00000) >> 21),
                ((time & 0x001F0000) >> 16),
                ((time & 0x0000F800) >> 11),
                ((time & 0x000007E0) >> 5),
                ((time & 0x0000001F) >> 0) * 2,
            )

            return datetime.datetime(*ymdhms, tzinfo=datetime.timezone.utc)
        except Exception:
            return "Invalid time"

    def read_string(self, index):
        result = ""
        while self.indata[index] != 0x00:
            result += chr(self.indata[index])
            index += 1
        return result

    def read_unicode_string(self, index):
        begin = end = index
        while self.indata[index] != 0x00:
            end += 1
            index += 1
        return self.clean_line(self.indata[begin:end].replace(b"\x00", b""))

    def format_linkFlags(self):
        return " | ".join(self.header.link_flags())

    def format_fileFlags(self):
        return " | ".join(self.header.file_flags())

    def print_short(self, pjson=False):
        out = ""
        if self.has_relative_path():
            out += self.data["relative_path"]
        if self.has_arguments():
            out += " " + self.data["command_line_arguments"]

        if pjson:
            print(json.dumps({"command": out}))
        else:
            print(out)

    def print_json(self, print_all=False):
        res = self.get_json(print_all)

        def _datetime_to_str(obj):
            if isinstance(obj, datetime.datetime):
                return obj.isoformat()
            return obj

        print(
            json.dumps(res, indent=4, separators=(",", ": "), default=_datetime_to_str)
        )

    def get_json(self, get_all=False):
        res = {
            "header": {
                "guid": self.header.link_cls_id(),
                "r_link_flags": self.header.r_link_flags(),
                "r_file_flags": self.header.r_file_flags(),
                "creation_time": self.header.creation_time(),
                "accessed_time": self.header.access_time(),
                "modified_time": self.header.write_time(),
                "file_size": self.header.file_size(),
                "icon_index": self.header.icon_index(),
                "windowstyle": self.header.window_style(),
                "hotkey": self.header.hot_key(),
                "r_hotkey": self.header.raw_hot_key(),
                "link_flags": self.header.link_flags(),
                "file_flags": self.header.file_flags(),
                "header_size": self.header.size(),
                "reserved0": self.header.reserved0(),
                "reserved1": self.header.reserved1(),
                "reserved2": self.header.reserved2(),
            },
            "data": self.string_data.as_dict(),
            "extra": self.extraBlocks,
        }

        if self.targets:
            res["target"] = {
                "size": self.targets.id_list_size(),
                "items": [x.as_item() for x in self.targets],
                "index": self._target_index,
            }

        res["link_info"] = {}
        if self.info:
            res["link_info"] = {
                "link_info_size": self.info.size(),
                "link_info_header_size": self.info.header_size(),
                "link_info_flags": self.info.flags(),
                "volume_id_offset": self.info.volume_id_offset(),
                "local_base_path_offset": self.info.local_base_path_offset(),
                "common_network_relative_link_offset": self.info.common_network_relative_link_offset(),
                "common_path_suffix_offset": self.info.common_path_suffix_offset(),
            }

            res["link_info"]["location_info"] = {}
            if type(self.info).__name__ == "local":
                res["link_info"]["local_base_path"] = self.info.local_base_path()
                res["link_info"]["common_path_suffix"] = self.info.common_path_suffix()
                res["link_info"]["location"] = self.info.location()
                res["link_info"]["location_info"] = {
                    "volume_id_size": self.info.volume_id_size(),
                    "r_drive_type": self.info.r_drive_type(),
                    "volume_label_offset": self.info.volume_label_offset(),
                    "drive_serial_number": self.info.drive_serial_number(),
                    "drive_type": self.info.drive_type(),
                    "volume_label": self.info.volume_label(),
                }

                if self.info.local_base_path_offset_unicode():
                    res["link_info"][
                        "local_base_path_offset_unicode"
                    ] = self.info.local_base_path_offset_unicode()
                if self.info.common_path_suffix_unicode():
                    res["link_info"][
                        "common_path_suffix_unicode"
                    ] = self.info.common_path_suffix_unicode()
                if self.info.volume_id():
                    res["link_info"]["volume_id"] = self.info.volume_id()
                if self.info.common_network_relative_link():
                    res["link_info"][
                        "common_network_relative_link"
                    ] = self.info.common_network_relative_link()
                if self.info.volume_label_unicode_offset():
                    res["link_info"][
                        "volume_label_unicode_offset"
                    ] = self.info.volume_label_unicode_offset()
                if self.info.volume_label_unicode():
                    res["link_info"][
                        "volume_label_unicode"
                    ] = self.info.volume_label_unicode()
                if self.info.local_base_unicode():
                    res["link_info"][
                        "local_base_unicode"
                    ] = self.info.local_base_unicode()
            elif type(self.info).__name__ == "network":
                res["link_info"][
                    "common_network_relative_link_size"
                ] = self.info.common_network_relative_link_size()
                res["link_info"][
                    "common_network_relative_link_flags"
                ] = self.info.common_network_relative_link_flags()
                res["link_info"]["net_name_offset"] = self.info.net_name_offset()
                res["link_info"]["drive_name_offset"] = self.info.drive_name_offset()
                res["link_info"][
                    "r_network_provider_type"
                ] = self.info.r_network_provider_type()
                if self.info.network_provider_type():
                    res["link_info"][
                        "network_provider_type"
                    ] = self.info.network_provider_type()
                if self.info.net_name_offset_unicode():
                    res["link_info"][
                        "net_name_offset_unicode"
                    ] = self.info.net_name_offset_unicode()
                if self.info.net_name_unicode():
                    res["link_info"]["net_name_unicode"] = self.info.net_name_unicode()
                if self.info.device_name_offset_unicode():
                    res["link_info"][
                        "device_name_offset_unicode"
                    ] = self.info.device_name_offset_unicode()
                if self.info.net_name():
                    res["link_info"]["net_name"] = self.info.net_name()
                if self.info.device_name():
                    res["link_info"]["device_name"] = self.info.device_name()

        if not get_all:
            res["header"].pop("header_size", None)
            res["header"].pop("reserved0", None)
            res["header"].pop("reserved1", None)
            res["header"].pop("reserved2", None)
            res["link_info"].pop("link_info_size", None)
            res["link_info"].pop("link_info_header_size", None)
            res["link_info"].pop("volume_id_offset", None)
            res["link_info"].pop("local_base_path_offset", None)
            res["link_info"].pop("common_network_relative_link_offset", None)
            res["link_info"].pop("common_path_suffix_offset", None)
            if "Local" in res["link_info"]:
                res["link_info"]["location_info"].pop("volume_id_size", None)
                res["link_info"]["location_info"].pop("volume_label_offset", None)
            if "Network" in res["link_info"]:
                res["link_info"]["location_info"].pop(
                    "common_network_relative_link_size", None
                )
                res["link_info"]["location_info"].pop("net_name_offset", None)
                res["link_info"]["location_info"].pop("device_name_offset", None)
            res["target"].pop("index", None)
            if "items" in res["target"]:
                for item in res["target"]["items"]:
                    if item:
                        item.pop("modification_time", None)

        return res


def main():
    arg_parser = argparse.ArgumentParser(description=__description__)
    arg_parser.add_argument(
        "-f",
        "--file",
        dest="file",
        required=True,
        help="absolute or relative path to the file",
    )
    arg_parser.add_argument(
        "-j", "--json", action="store_true", help="print output in JSON"
    )
    arg_parser.add_argument(
        "-d",
        "--json_debug",
        action="store_true",
        help="print all extracted data in JSON (i.e. offsets and sizes)",
    )
    arg_parser.add_argument(
        "-D", "--debug", action="store_true", help="print debug info"
    )
    args = arg_parser.parse_args()

    with open(args.file, "rb") as file:
        lnk = lnk_file(fhandle=file, debug=args.debug)
        if args.json:
            lnk.print_json(args.json_debug)
        else:
            lnk.print_lnk_file()


if __name__ == "__main__":
    main()
