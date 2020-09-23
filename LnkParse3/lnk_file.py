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


class lnk_file(object):
    def __init__(self, fhandle=None, indata=None, debug=False):
        self.define_static()

        if fhandle:
            self.indata = fhandle.read()
        elif indata:
            self.indata = indata

        self.debug = debug

        self.loc_information = {}
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

        self.NETWORK_PROVIDER_TYPES = {
            "0x1A000": "WNNC_NET_AVID",
            "0x1B000": "WNNC_NET_DOCUSPACE",
            "0x1C000": "WNNC_NET_MANGOSOFT",
            "0x1D000": "WNNC_NET_SERNET",
            "0X1E000": "WNNC_NET_RIVERFRONT1",
            "0x1F000": "WNNC_NET_RIVERFRONT2",
            "0x20000": "WNNC_NET_DECORB",
            "0x21000": "WNNC_NET_PROTSTOR",
            "0x22000": "WNNC_NET_FJ_REDIR",
            "0x23000": "WNNC_NET_DISTINCT",
            "0x24000": "WNNC_NET_TWINS",
            "0x25000": "WNNC_NET_RDR2SAMPLE",
            "0x26000": "WNNC_NET_CSC",
            "0x27000": "WNNC_NET_3IN1",
            "0x29000": "WNNC_NET_EXTENDNET",
            "0x2A000": "WNNC_NET_STAC",
            "0x2B000": "WNNC_NET_FOXBAT",
            "0x2C000": "WNNC_NET_YAHOO",
            "0x2D000": "WNNC_NET_EXIFS",
            "0x2E000": "WNNC_NET_DAV",
            "0x2F000": "WNNC_NET_KNOWARE",
            "0x30000": "WNNC_NET_OBJECT_DIRE",
            "0x31000": "WNNC_NET_MASFAX",
            "0x32000": "WNNC_NET_HOB_NFS",
            "0x33000": "WNNC_NET_SHIVA",
            "0x34000": "WNNC_NET_IBMAL",
            "0x35000": "WNNC_NET_LOCK",
            "0x36000": "WNNC_NET_TERMSRV",
            "0x37000": "WNNC_NET_SRT",
            "0x38000": "WNNC_NET_QUINCY",
            "0x39000": "WNNC_NET_OPENAFS",
            "0X3A000": "WNNC_NET_AVID1",
            "0x3B000": "WNNC_NET_DFS",
            "0x3C000": "WNNC_NET_KWNP",
            "0x3D000": "WNNC_NET_ZENWORKS",
            "0x3E000": "WNNC_NET_DRIVEONWEB",
            "0x3F000": "WNNC_NET_VMWARE",
            "0x40000": "WNNC_NET_RSFX",
            "0x41000": "WNNC_NET_MFILES",
            "0x42000": "WNNC_NET_MS_NFS",
            "0x43000": "WNNC_NET_GOOGLE",
        }
        self.DRIVE_TYPES = [
            "DRIVE_UNKNOWN",
            "DRIVE_NO_ROOT_DIR",
            "DRIVE_REMOVABLE",
            "DRIVE_FIXED",
            "DRIVE_REMOTE",
            "DRIVE_CDROM",
            "DRIVE_RAMDISK",
        ]

    @staticmethod
    def clean_line(rstring):
        return "".join(chr(i) for i in rstring if 128 > i > 20)

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
            "link_info_size": struct.unpack("<I", self.indata[index : index + 4])[0],
            "link_info_header_size": struct.unpack(
                "<I", self.indata[index + 4 : index + 8]
            )[0],
            "link_info_flags": struct.unpack("<I", self.indata[index + 8 : index + 12])[
                0
            ],
            "volume_id_offset": struct.unpack(
                "<I", self.indata[index + 12 : index + 16]
            )[0],
            "local_base_path_offset": struct.unpack(
                "<I", self.indata[index + 16 : index + 20]
            )[0],
            "common_network_relative_link_offset": struct.unpack(
                "<I", self.indata[index + 20 : index + 24]
            )[0],
            "common_path_suffix_offset": struct.unpack(
                "<I", self.indata[index + 24 : index + 28]
            )[0],
        }

        if self.loc_information["link_info_flags"] & 0x0001:
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
            if self.loc_information["link_info_header_size"] >= 36:
                self.loc_information["local_base_path_offset_unicode"] = struct.unpack(
                    "<I", self.indata[index + 28 : index + 32]
                )[0]
                local_index = (
                    index + self.loc_information["local_base_path_offset_unicode"]
                )
                self.loc_information[
                    "local_base_path_offset_unicode"
                ] = self.read_unicode_string(local_index)

                self.loc_information[
                    "common_path_suffix_offset_unicode"
                ] = struct.unpack("<I", self.indata[index + 32 : index + 36])[0]
                local_index = (
                    index + self.loc_information["common_path_suffix_offset_unicode"]
                )
                self.loc_information[
                    "common_path_suffix_unicode"
                ] = self.read_unicode_string(local_index)
            else:
                local_index = index + self.loc_information["local_base_path_offset"]
                self.loc_information["local_base_path"] = self.read_string(local_index)

                local_index = index + self.loc_information["common_path_suffix_offset"]
                self.loc_information["common_path_suffix"] = self.read_string(
                    local_index
                )

            local_index = index + self.loc_information["volume_id_offset"]
            self.loc_information["location"] = "Local"
            self.loc_information["location_info"] = {
                "volume_id_size": struct.unpack(
                    "<I", self.indata[local_index + 0 : local_index + 4]
                )[0],
                "r_drive_type": struct.unpack(
                    "<I", self.indata[local_index + 4 : local_index + 8]
                )[0],
                "drive_serial_number": hex(
                    struct.unpack(
                        "<I", self.indata[local_index + 8 : local_index + 12]
                    )[0]
                ),
                "volume_label_offset": struct.unpack(
                    "<I", self.indata[local_index + 12 : local_index + 16]
                )[0],
            }

            if self.loc_information["location_info"]["r_drive_type"] < len(
                self.DRIVE_TYPES
            ):
                self.loc_information["location_info"]["drive_type"] = self.DRIVE_TYPES[
                    self.loc_information["location_info"]["r_drive_type"]
                ]

            if self.loc_information["location_info"]["volume_label_offset"] != 20:
                local_index = (
                    index
                    + self.loc_information["volume_id_offset"]
                    + self.loc_information["location_info"]["volume_label_offset"]
                )
                self.loc_information["location_info"][
                    "volume_label"
                ] = self.read_string(local_index)
            else:
                self.loc_information["location_info"][
                    "volume_label_offset_unicode"
                ] = struct.unpack(
                    "<I", self.indata[local_index + 16 : local_index + 20]
                )[
                    0
                ]
                local_index = (
                    index
                    + self.loc_information["volume_id_offset"]
                    + self.loc_information["location_info"][
                        "volume_label_offset_unicode"
                    ]
                )
                self.loc_information["location_info"][
                    "volume_label_unicode"
                ] = self.read_unicode_string(local_index)

        elif self.loc_information["link_info_flags"] & 0x0002:
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
            local_index = (
                index + self.loc_information["common_network_relative_link_offset"]
            )
            self.loc_information["location"] = "Network"
            self.loc_information["location_info"] = {
                "common_network_relative_link_size": struct.unpack(
                    "<I", self.indata[local_index + 0 : local_index + 4]
                )[0],
                "common_retwork_relative_link_flags": struct.unpack(
                    "<I", self.indata[local_index + 4 : local_index + 8]
                )[0],
                "net_name_offset": struct.unpack(
                    "<I", self.indata[local_index + 8 : local_index + 12]
                )[0],
                "device_name_offset": struct.unpack(
                    "<I", self.indata[local_index + 12 : local_index + 16]
                )[0],
                "r_network_provider_type": hex(
                    struct.unpack(
                        "<I", self.indata[local_index + 16 : local_index + 20]
                    )[0]
                ),
            }

            if (
                self.loc_information["location_info"][
                    "common_retwork_relative_link_flags"
                ]
                & 0x0002
            ):
                if (
                    self.loc_information["location_info"]["r_network_provider_type"]
                    in self.NETWORK_PROVIDER_TYPES
                ):
                    self.loc_information["location_info"][
                        "network_provider_type"
                    ] = self.NETWORK_PROVIDER_TYPES[
                        self.loc_information["location_info"]["r_network_provider_type"]
                    ]

            if self.loc_information["location_info"]["net_name_offset"] > 20:
                self.loc_information["location_info"][
                    "net_name_offset_unicode"
                ] = struct.unpack("<I", self.indata[local_index + 20 : index + 24])[0]
                local_index = (
                    index
                    + self.loc_information["location_info"][
                        "common_network_relative_link_offset"
                    ]
                    + self.loc_information["location_info"]["net_name_offset_unicode"]
                )
                self.loc_information["location_info"][
                    "net_name_unicode"
                ] = self.read_unicode_string(local_index)

                self.loc_information["location_info"][
                    "device_name_offset_unicode"
                ] = struct.unpack("<I", self.indata[local_index + 24 : index + 28])[0]
                local_index = (
                    index
                    + self.loc_information["location_info"][
                        "common_network_relative_link_offset"
                    ]
                    + self.loc_information["location_info"][
                        "device_name_offset_unicode"
                    ]
                )
                self.loc_information["location_info"][
                    "device_name_unicode"
                ] = self.read_unicode_string(local_index)
            else:
                local_index = (
                    index
                    + self.loc_information["common_network_relative_link_offset"]
                    + self.loc_information["location_info"]["net_name_offset"]
                )
                self.loc_information["location_info"]["net_name"] = self.read_string(
                    local_index
                )

                local_index = (
                    index
                    + self.loc_information["common_network_relative_link_offset"]
                    + self.loc_information["location_info"]["device_name_offset"]
                )
                self.loc_information["location_info"]["device_name"] = self.read_string(
                    local_index
                )

    def parse_string_data(self, index):
        u_mult = 1
        if self.is_unicode():
            u_mult = 2

        if self.has_name():
            index, self.data["description"] = self.read_stringData(index, u_mult)

        if self.has_relative_path():
            index, self.data["relative_path"] = self.read_stringData(index, u_mult)

        if self.has_working_dir():
            index, self.data["working_directory"] = self.read_stringData(index, u_mult)

        if self.has_arguments():
            index, self.data["command_line_arguments"] = self.read_stringData(
                index, u_mult
            )

        if self.has_icon_location():
            index, self.data["icon_location"] = self.read_stringData(index, u_mult)

        return index

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
        if self.has_link_info() and self.force_no_link_info() == False:
            try:
                self.parse_link_information(index)
                index += self.loc_information["link_info_size"]
            except Exception as e:
                if self.debug:
                    print("Exception parsing Location information: %s" % e)
                return False

        # Parse String Data
        try:
            index = self.parse_string_data(index)
        except Exception as e:
            if self.debug:
                print("Exception in parsing data: %s" % e)
            return False

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

        for rline in self.data:
            print("\t%s: %s" % (rline, self.data[rline]))

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

    def read_stringData(self, index, u_mult):
        string_size = struct.unpack("<H", self.indata[index : index + 2])[0] * u_mult
        string = self.clean_line(
            self.indata[index + 2 : index + 2 + string_size].replace(b"\x00", b"")
        )
        new_index = index + string_size + 2
        return new_index, string

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
            "data": self.data,
            "link_info": self.loc_information,
            "extra": self.extraBlocks,
        }

        if self.targets:
            res["target"] = {
                "size": self.targets.id_list_size(),
                "items": [x.as_item() for x in self.targets],
                "index": self._target_index,
            }

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
