from struct import unpack
from LnkParse3.target.unknown import unknown
from LnkParse3.target.root_folder import root_folder
from LnkParse3.target.my_computer import my_computer
from LnkParse3.target.shell_fs_folder import shell_fs_folder
from LnkParse3.target.network_location import network_location
from LnkParse3.target.compressed_folder import compressed_folder
from LnkParse3.target.internet import internet
from LnkParse3.target.control_panel import control_panel
from LnkParse3.target.printers import printers
from LnkParse3.target.common_places_folder import common_places_folder
from LnkParse3.target.users_files_folder import users_files_folder


class target_factory:
    # https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#3-type-indicator-based-shell-items
    SHELL_ITEM_CLASSES = {
        0x00: unknown,
        0x01: unknown,
        0x17: unknown,
        0x1E: root_folder,
        0x1F: root_folder,
        0x20: my_computer,
        0x30: shell_fs_folder,
        0x40: network_location,
        0x52: compressed_folder,
        0x61: internet,
        0x70: control_panel,
        0x71: control_panel,
        0x72: printers,
        0x73: common_places_folder,
        0x74: users_files_folder,
        0x76: unknown,
        0x80: unknown,
        0xFF: unknown,
    }

    def __init__(self, indata):
        self._target = {}
        self._raw = indata

    def item_size(self):
        """ItemIDSize (2 bytes):
        A 16-bit, unsigned integer that specifies the size, in bytes, of the
        ItemID structure, including the ItemIDSize field.
        """
        start, end = 0, 2
        size = unpack("<H", self._raw[start:end])[0]
        return size

    def item_type(self):
        """
        Peek item type before creating objects
        """
        start, end = 2, 3
        item_type = unpack("<B", self._raw[start:end])[0]
        return item_type

    def target_class(self):
        if self.item_size() == 0:
            # TerminalID
            return None

        item_type = self.item_type()
        classes = self.SHELL_ITEM_CLASSES

        # TODO: ControlPanelShellItems
        # https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#43-control-panel-shell-items
        # if item_type == 0x00:

        # XXX: Move to table
        if 0x20 < item_type <= 0x2F:
            target = classes[0x20]
        elif 0x30 < item_type <= 0x3F:
            target = classes[0x30]
        elif 0x40 < item_type <= 0x4F:
            target = classes[0x40]
        else:
            target = classes[item_type]

        return target
