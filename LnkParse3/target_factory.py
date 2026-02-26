import warnings
from struct import unpack

from LnkParse3.target.common_places_folder import CommonPlacesFolder
from LnkParse3.target.compressed_folder import CompressedFolder
from LnkParse3.target.control_panel import ControlPanel
from LnkParse3.target.control_panel_category import ControlPanelCategory
from LnkParse3.target.control_panel_cpl import ControlPanelCPL
from LnkParse3.target.internet import Internet
from LnkParse3.target.my_computer import MyComputer
from LnkParse3.target.network_location import NetworkLocation
from LnkParse3.target.printers import Printers
from LnkParse3.target.root_folder import RootFolder
from LnkParse3.target.shell_fs_folder import ShellFSFolder
from LnkParse3.target.unknown import Unknown
from LnkParse3.target.users_files_folder import UsersFilesFolder


class TargetFactory:
    # https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#3-type-indicator-based-shell-items
    SHELL_ITEM_CLASSES = {
        0x00: ControlPanelCPL,
        0x01: ControlPanelCategory,
        0x1E: RootFolder,
        0x1F: RootFolder,
        0x20: MyComputer,
        0x30: ShellFSFolder,
        0x40: NetworkLocation,
        0x52: CompressedFolder,
        0x61: Internet,
        0x70: ControlPanel,
        0x71: ControlPanel,
        0x72: Printers,
        0x73: CommonPlacesFolder,
        0x74: UsersFilesFolder,
    }

    @classmethod
    def get_shell_item_classes(cls, item_type):
        if item_type not in cls.SHELL_ITEM_CLASSES:
            msg = (
                f"Not implemented item_type 0x{item_type:02X} "
                "in TargetFactory.SHELL_ITEM_CLASSES. "
                f"Use fallback value: {Unknown!r}."
            )
            warnings.warn(msg)
            return Unknown
        return cls.SHELL_ITEM_CLASSES[item_type]

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

    # dup: ./targets/shell_fs_folder.py flags()
    # dup: ./targets/my_computer.py flags()
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

        # XXX: Move to table
        # 0x20, 0x30, and 0x40 should have an 0x70 bitmask applied per
        # https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc
        masked_item_type = item_type & 0x70
        if masked_item_type in [0x20, 0x30, 0x40]:
            target = self.get_shell_item_classes(masked_item_type)
        else:
            target = self.get_shell_item_classes(item_type)

        return target
