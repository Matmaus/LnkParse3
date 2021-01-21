#!/usr/bin/env python3

__description__ = "Windows Shortcut file (LNK) parser"
__author__ = "Matmaus"
__version__ = "1.0.0"

import json
import datetime
import argparse
from subprocess import list2cmdline

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
        def cprint(text, level=0):
            SPACING = 3
            UNWANTED_TRAITS = ["offset", "reserved", "size"]
            text = str(text)
            if print_all or all(x not in text.lower() for x in UNWANTED_TRAITS):
                print(" " * (level * SPACING) + text)  # add leading spaces

        def nice_id(identifier):
            return identifier.capitalize().replace("_", " ")

        # TODO recursive nice print
        cprint("Windows Shortcut Information:")
        cprint("Header Size: %s" % self.header.size(), 1)
        cprint("Link CLSID: %s" % self.header.link_cls_id(), 1)
        cprint(
            "Link Flags: %s - (%s)"
            % (self.format_linkFlags(), self.header.r_link_flags()),
            1,
        )
        cprint(
            "File Flags: %s - (%s)"
            % (self.format_fileFlags(), self.header.r_file_flags()),
            1,
        )
        cprint("")
        cprint("Creation Timestamp: %s" % (self.header.creation_time()), 1)
        cprint("Modified Timestamp: %s" % (self.header.write_time()), 1)
        cprint("Accessed Timestamp: %s" % (self.header.access_time()), 1)
        cprint("")
        cprint(
            "File Size: %s (r: %s)"
            % (str(self.header.file_size()), str(len(self.indata))),
            1,
        )
        cprint("Icon Index: %s " % (str(self.header.icon_index())), 1)
        cprint("Window Style: %s " % (str(self.header.window_style())), 1)
        cprint("HotKey: %s " % (str(self.header.hot_key())), 1)
        cprint("Reserved0: %s" % self.header.reserved0(), 1)
        cprint("Reserved1: %s" % self.header.reserved1(), 1)
        cprint("Reserved2: %s" % self.header.reserved2(), 1)
        cprint("")

        if self.targets:
            cprint("TARGETS:", 1)
            cprint("Size: %s" % self.targets.id_list_size(), 2)
            cprint("Index: %s" % self._target_index, 2)
            cprint("ITEMS:", 2)
            for target in self.targets:
                target_item = target.as_item()
                if target_item is None:
                    continue
                cprint(target_item["class"], 3)
                for key, value in target_item.items():
                    if key != "class":
                        cprint(f"{nice_id(key)}: {value}", 4)
            cprint("")

        if self.info:
            cprint("LINK INFO:", 1)
            cprint("Link info size: %s" % self.info.size(), 2)
            cprint("Link info header size: %s" % self.info.header_size(), 2)
            cprint("Link info flags: %s" % self.info.flags(), 2)
            cprint("Volume ID offset: %s" % self.info.volume_id_offset(), 2)
            cprint("Local base path offset: %s" % self.info.local_base_path_offset(), 2)
            cprint(
                "Common network relative link offset: %s"
                % self.info.common_network_relative_link_offset(),
                2,
            )
            cprint(
                "Common path suffix offset: %s" % self.info.common_path_suffix_offset(),
                2,
            )
            if type(self.info).__name__ == "Local":
                cprint("Local_base_path: %s" % self.info.local_base_path(), 2)
                cprint("Common path suffix: %s" % self.info.common_path_suffix(), 2)

                cprint("LOCAL:", 2)
                cprint("Volume ID size: %s" % self.info.volume_id_size(), 3)
                cprint("Drive type: %s" % self.info.r_drive_type(), 3)
                cprint("Volume label offset: %s" % self.info.volume_label_offset(), 3)
                cprint("Drive serial number: %s" % self.info.drive_serial_number(), 3)
                cprint("Drive type: %s" % self.info.drive_type(), 3)
                cprint("Volume label: %s" % self.info.volume_label(), 3)
                if self.info.local_base_path_offset_unicode():
                    cprint(
                        "Local base path offset unicode: %s"
                        % self.info.local_base_path_offset_unicode(),
                        3,
                    )
                if self.info.common_path_suffix_unicode():
                    cprint(
                        "Common path suffix unicode: %s"
                        % self.info.common_path_suffix_unicode(),
                        3,
                    )
                if self.info.volume_id():
                    cprint("Volume id: %s" % self.info.volume_id(), 3)
                if self.info.common_network_relative_link():
                    cprint(
                        "Common network relative link: %s"
                        % self.info.common_network_relative_link(),
                        3,
                    )
                if self.info.volume_label_unicode_offset():
                    cprint(
                        "Volume label unicode offset: %s"
                        % self.info.volume_label_unicode_offset(),
                        3,
                    )
                if self.info.volume_label_unicode():
                    cprint(
                        "Volume label unicode: %s" % self.info.volume_label_unicode(), 3
                    )
                if self.info.local_base_unicode():
                    cprint("Local base unicode: %s" % self.info.local_base_unicode(), 3)
            elif type(self.info).__name__ == "Network":
                cprint(
                    "Common network relative link size: %s"
                    % self.info.common_network_relative_link_size(),
                    3,
                )
                cprint(
                    "Common network relative link flags: %s"
                    % self.info.common_network_relative_link_flags(),
                    3,
                )
                cprint("Net name offset: %s" % self.info.net_name_offset(), 3)
                cprint("Device name offset: %s" % self.info.device_name_offset(), 3)
                cprint(
                    "Network provider type: %s" % self.info.r_network_provider_type(), 3
                )
                if self.info.network_provider_type():
                    cprint(
                        "Network provider type: %s" % self.info.network_provider_type(),
                        3,
                    )
                if self.info.net_name_offset_unicode():
                    cprint(
                        "net_name_offset_unicode: %s"
                        % self.info.net_name_offset_unicode(),
                        3,
                    )
                if self.info.net_name_unicode():
                    cprint("net_name_unicode: %s" % self.info.net_name_unicode(), 3)
                if self.info.device_name_offset_unicode():
                    cprint(
                        "device_name_offset_unicode: %s"
                        % self.info.device_name_offset_unicode(),
                        3,
                    )
                if self.info.net_name():
                    cprint("net_name: %s" % self.info.net_name(), 3)
                if self.info.device_name():
                    cprint("device_name: %s" % self.info.device_name(), 3)
            cprint("")

        cprint("DATA", 1)
        for key, value in self.string_data.as_dict().items():
            cprint("%s: %s" % (nice_id(key), value), 2)
        cprint("")

        cprint("EXTRA BLOCKS:", 1)
        for extra_key, extra_value in self.extras.as_dict().items():
            cprint(f"{extra_key}", 2)
            for key, value in extra_value.items():
                cprint(f"{nice_id(key)}: {value}", 3)

    def format_linkFlags(self):
        return " | ".join(self.header.link_flags())

    def format_fileFlags(self):
        return " | ".join(self.header.file_flags())

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
            "data": self.string_data.as_dict(),
            "extra": self.extras.as_dict(),
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

            res["link_info"]["location_info"] = {}
            if type(self.info).__name__ == "Local":
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
