#!/usr/bin/env python3

__description__ = "Windows Shortcut file (LNK) parser"
__author__ = "Matúš Jasnický"
__version__ = "0.3.3"

import json
import datetime
import argparse

from LnkParse3.lnk_header import lnk_header
from LnkParse3.lnk_targets import lnk_targets
from LnkParse3.lnk_info import lnk_info
from LnkParse3.info_factory import info_factory
from LnkParse3.string_data import string_data
from LnkParse3.extra_data import extra_data


class lnk_file(object):
    def __init__(self, fhandle=None, indata=None, debug=False):
        if fhandle:
            self.indata = fhandle.read()
        elif indata:
            self.indata = indata

        self.debug = debug

        self.data = {}

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
        self.extras = extra_data(indata=self.indata[index:])

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

        for extra in self.extras:
            print(f"\t\t{extra.name()}")
            for key, value in extra.as_dict().items():
                print(f"\t\t\t[{key}] {value}")

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
            "extra": {extra.name(): extra.as_dict() for extra in self.extras},
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
                    res["link_info"]["location_info"][
                        "local_base_path_offset_unicode"
                    ] = self.info.local_base_path_offset_unicode()
                if self.info.common_path_suffix_unicode():
                    res["link_info"]["location_info"][
                        "common_path_suffix_unicode"
                    ] = self.info.common_path_suffix_unicode()
                if self.info.volume_id():
                    res["link_info"]["location_info"][
                        "volume_id"
                    ] = self.info.volume_id()
                if self.info.common_network_relative_link():
                    res["link_info"]["location_info"][
                        "common_network_relative_link"
                    ] = self.info.common_network_relative_link()
                if self.info.volume_label_unicode_offset():
                    res["link_info"]["location_info"][
                        "volume_label_unicode_offset"
                    ] = self.info.volume_label_unicode_offset()
                if self.info.volume_label_unicode():
                    res["link_info"]["location_info"][
                        "volume_label_unicode"
                    ] = self.info.volume_label_unicode()
                if self.info.local_base_unicode():
                    res["link_info"]["location_info"][
                        "local_base_unicode"
                    ] = self.info.local_base_unicode()
            elif type(self.info).__name__ == "network":
                res["link_info"]["location_info"] = {
                    "common_network_relative_link_size": self.info.common_network_relative_link_size(),
                    "common_network_relative_link_flags": self.info.common_network_relative_link_flags(),
                    "net_name_offset": self.info.net_name_offset(),
                    "drive_name_offset": self.info.drive_name_offset(),
                    "r_network_provider_type": self.info.r_network_provider_type(),
                }
                if self.info.network_provider_type():
                    res["link_info"]["location_info"][
                        "network_provider_type"
                    ] = self.info.network_provider_type()
                if self.info.net_name_offset_unicode():
                    res["link_info"]["location_info"][
                        "net_name_offset_unicode"
                    ] = self.info.net_name_offset_unicode()
                if self.info.net_name_unicode():
                    res["link_info"]["location_info"][
                        "net_name_unicode"
                    ] = self.info.net_name_unicode()
                if self.info.device_name_offset_unicode():
                    res["link_info"]["location_info"][
                        "device_name_offset_unicode"
                    ] = self.info.device_name_offset_unicode()
                if self.info.net_name():
                    res["link_info"]["location_info"]["net_name"] = self.info.net_name()
                if self.info.device_name():
                    res["link_info"]["location_info"][
                        "device_name"
                    ] = self.info.device_name()

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
