#!/usr/bin/env python3

__description__ = "Windows Shortcut file (LNK) parser"
__author__ = "Matmaus"
__version__ = "1.5.0"

import json
import datetime
import argparse
from subprocess import list2cmdline
import re
import textwrap

import yaml

from LnkParse3.lnk_header import LnkHeader
from LnkParse3.lnk_targets import LnkTargets
from LnkParse3.lnk_info import LnkInfo
from LnkParse3.info_factory import InfoFactory
from LnkParse3.string_data import StringData
from LnkParse3.extra_data import ExtraData


class LnkFile(object):
    def __init__(self, fhandle=None, indata=None, cp=None):
        if fhandle:
            self.indata = fhandle.read()
        elif indata:
            self.indata = indata

        self.cp = cp

        self.process()

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

    def process(self):
        index = 0

        # Parse header
        self.header = LnkHeader(indata=self.indata)
        index += self.header.size()

        # XXX: json
        self._target_index = index + 2

        # Parse ID List
        self.targets = None
        if self.has_target_id_list():
            self.targets = LnkTargets(indata=self.indata[index:], cp=self.cp)
            index += self.targets.size()

        # Parse Link Info
        self.info = None
        if self.has_link_info() and not self.force_no_link_info():
            info = LnkInfo(indata=self.indata[index:], cp=self.cp)
            info_class = InfoFactory(info).info_class()
            if info_class:
                self.info = info_class(indata=self.indata[index:], cp=self.cp)
                index += self.info.size()

        # Parse String Data
        self.string_data = StringData(self, indata=self.indata[index:], cp=self.cp)
        index += self.string_data.size()

        # Parse Extra Data
        self.extras = ExtraData(indata=self.indata[index:], cp=self.cp)

    def print_lnk_file(self, print_all=False):
        res = self.get_json(print_all)

        def nice_id(identifier, uppercase=False):
            identifier = re.sub("^r_", "", identifier, 1)
            if uppercase or identifier.upper() == identifier:
                return identifier.upper().replace("_", " ")
            return identifier.capitalize().replace("_", " ")

        def make_keys_nice(input, uppercase=False):
            if isinstance(input, list):
                return [make_keys_nice(item) for item in input]
            if isinstance(input, dict):
                if "class" in input:
                    key = input.pop("class")
                    return {key: make_keys_nice(input)}
                result = {}
                for key, value in input.items():
                    result[nice_id(key, uppercase)] = make_keys_nice(value)
                return result
            return input

        # remove r_hotkey from header and reformat flags
        res["header"].pop("r_hotkey")
        res["header"]["link_flags"] = self.format_linkFlags()
        res["header"]["file_flags"] = self.format_fileFlags()

        res_json = make_keys_nice(res, uppercase=True)

        # insert placeholders for empty lines
        res_json = {"EMPTY_LINE_PLACEHOLDER" + k: v for k, v in res_json.items()}

        # remove header key
        new_res_json = res_json["EMPTY_LINE_PLACEHOLDERHEADER"]
        res_json.pop("EMPTY_LINE_PLACEHOLDERHEADER")
        new_res_json.update(res_json)

        res_yaml = yaml.dump(
            new_res_json, indent=3, sort_keys=False, width=132, allow_unicode=True
        )

        # replace palceholders for empty lines
        res_yaml = res_yaml.replace("EMPTY_LINE_PLACEHOLDER", "\n")

        print("Windows Shortcut Information:")
        print(textwrap.indent(res_yaml, "   "))

    def format_linkFlags(self):
        raw_flags = self.header.r_link_flags()
        suffix = f" - ({raw_flags})" if raw_flags else f"({raw_flags})"
        return " | ".join(self.header.link_flags()) + suffix

    def format_fileFlags(self):
        raw_flags = self.header.r_file_flags()
        suffix = f" - ({raw_flags})" if raw_flags else f"({raw_flags})"
        return " | ".join(self.header.file_flags()) + suffix

    # FIXME: Simple concat of path and arguments
    @property
    def lnk_command(self):
        out = []

        if self.has_relative_path():
            relative_path = self.string_data.relative_path()
            out.append(list2cmdline([relative_path]))

        if self.has_arguments():
            out.append(self.string_data.command_line_arguments())

        return " ".join(out)

    def print_shortcut_target(self, pjson=False):
        out = self.lnk_command

        if pjson:
            print(json.dumps({"shortcut_target": out}))
        else:
            print(out)

    def print_json(self, print_all=False):
        res = self.get_json(print_all)

        def _datetime_to_str(obj):
            if isinstance(obj, datetime.datetime):
                return obj.replace(microsecond=0).isoformat()
            return obj

        print(
            json.dumps(
                res,
                indent=4,
                separators=(",", ": "),
                default=_datetime_to_str,
                sort_keys=True,
            )
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
        }

        if self.targets:
            res["target"] = {
                "size": self.targets.id_list_size(),
                "items": self.targets.as_list(),
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

            if self.info.local_base_path_offset():
                res["link_info"]["local_base_path"] = self.info.local_base_path()
            if self.info.common_path_suffix_offset():
                res["link_info"]["common_path_suffix"] = self.info.common_path_suffix()
            if self.info.local_base_path_offset_unicode():
                res["link_info"][
                    "local_base_path_offset_unicode"
                ] = self.info.local_base_path_offset_unicode()
                res["link_info"][
                    "local_base_path_unicode"
                ] = self.info.local_base_path_unicode()
            if self.info.common_path_suffix_offset_unicode():
                res["link_info"][
                    "common_path_suffix_offset_unicode"
                ] = self.info.common_path_suffix_offset_unicode()
                res["link_info"][
                    "common_path_suffix_unicode"
                ] = self.info.common_path_suffix_unicode()

            res["link_info"]["location_info"] = {}
            if type(self.info).__name__ == "Local":
                res["link_info"]["location"] = self.info.location()

                res["link_info"]["location_info"] = {
                    "volume_id_size": self.info.volume_id_size(),
                    "r_drive_type": self.info.r_drive_type(),
                    "volume_label_offset": self.info.volume_label_offset(),
                    "drive_serial_number": self.info.drive_serial_number(),
                    "drive_type": self.info.drive_type(),
                    "volume_label": self.info.volume_label(),
                }

                if self.info.common_network_relative_link():
                    res["link_info"]["location_info"][
                        "common_network_relative_link"
                    ] = self.info.common_network_relative_link()
                if self.info.volume_label_unicode_offset():
                    res["link_info"]["location_info"][
                        "volume_label_unicode_offset"
                    ] = self.info.volume_label_unicode_offset()
                    res["link_info"]["location_info"][
                        "volume_label_unicode"
                    ] = self.info.volume_label_unicode()
            elif type(self.info).__name__ == "Network":
                res["link_info"]["location"] = self.info.location()
                res["link_info"]["location_info"] = {
                    "common_network_relative_link_size": self.info.common_network_relative_link_size(),
                    "common_network_relative_link_flags": self.info.common_network_relative_link_flags(),
                    "net_name_offset": self.info.net_name_offset(),
                    "device_name_offset": self.info.device_name_offset(),
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
                    res["link_info"]["location_info"][
                        "net_name_unicode"
                    ] = self.info.net_name_unicode()
                if self.info.device_name_offset_unicode():
                    res["link_info"]["location_info"][
                        "device_name_offset_unicode"
                    ] = self.info.device_name_offset_unicode()
                    res["link_info"]["location_info"][
                        "device_name_unicode"
                    ] = self.info.device_name_unicode()
                if self.info.net_name():
                    res["link_info"]["location_info"]["net_name"] = self.info.net_name()
                if self.info.device_name():
                    res["link_info"]["location_info"][
                        "device_name"
                    ] = self.info.device_name()

        res["data"] = self.string_data.as_dict()
        res["extra"] = self.extras.as_dict()

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
            if (
                "location" in res["link_info"]
                and "Local" in res["link_info"]["location"]
            ):
                res["link_info"]["location_info"].pop("volume_id_size", None)
                res["link_info"]["location_info"].pop("volume_label_offset", None)
            if (
                "location" in res["link_info"]
                and "Network" in res["link_info"]["location"]
            ):
                res["link_info"]["location_info"].pop(
                    "common_network_relative_link_size", None
                )
                res["link_info"]["location_info"].pop("net_name_offset", None)
                res["link_info"]["location_info"].pop("device_name_offset", None)

            if "target" in res:
                res["target"].pop("index", None)
                res["target"].pop("size", None)
                if "items" in res["target"]:
                    for item in res["target"]["items"]:
                        if item:
                            item.pop("modification_time", None)

        return res


def main():
    arg_parser = argparse.ArgumentParser(description=__description__)
    arg_parser.add_argument(
        dest="file",
        metavar="FILE",
        help="absolute or relative path to the file",
    )
    arg_parser.add_argument(
        "-t", "--target", action="store_true", help="print shortcut target only"
    )
    arg_parser.add_argument(
        "-j", "--json", action="store_true", help="print output in JSON"
    )
    arg_parser.add_argument(
        "-c",
        "--codepage",
        dest="cp",
        default="cp1252",
        help="set codepage of ASCII strings",
    )
    arg_parser.add_argument(
        "-a",
        "--all",
        dest="print_all",
        action="store_true",
        help="print all extracted data (i.e. offsets and sizes)",
    )
    args = arg_parser.parse_args()

    with open(args.file, "rb") as file:
        lnk = LnkFile(fhandle=file, cp=args.cp)
        if args.target:
            lnk.print_shortcut_target(pjson=args.json)
        elif args.json:
            lnk.print_json(args.print_all)
        else:
            lnk.print_lnk_file(args.print_all)


if __name__ == "__main__":
    main()
