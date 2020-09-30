from struct import unpack
from LnkParse3.target.unknown import Unknown
from LnkParse3.target.root_folder import RootFolder
from LnkParse3.target.my_computer import MyComputer
from LnkParse3.target.shell_fs_folder import ShellFSFolder
from LnkParse3.target.network_location import NetworkLocation
from LnkParse3.target.compressed_folder import CompressedFolder
from LnkParse3.target.internet import Internet
from LnkParse3.target.control_panel import ControlPanel
from LnkParse3.target.printers import Printers
from LnkParse3.target.common_places_folder import CommonPlacesFolder
from LnkParse3.target.users_files_folder import UsersFilesFolder


class TargetFactory:
    # https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#3-type-indicator-based-shell-items
    SHELL_ITEM_CLASSES = {
        0x00: Unknown,
        0x01: Unknown,
        0x17: Unknown,
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
        0x76: Unknown,
        0x80: Unknown,
        0xFF: Unknown,
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
