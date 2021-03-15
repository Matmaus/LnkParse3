from struct import unpack
from LnkParse3.target.lnk_target_base import LnkTargetBase
from LnkParse3.decorators import uuid

"""
----------------------------------------------------------------------
|             0-7b                 |              8-15b              |
----------------------------------------------------------------------
|   ClassTypeIndicator == 0x1F     | SortIndex == (0x00,0x42,...0x80)|
----------------------------------------------------------------------
|                     <GUID> ShellFolderID                           |
|                             16 B                                   |
----------------------------------------------------------------------
|                         ExtensionBlock                             |
|                              ? B                                   |
----------------------------------------------------------------------
"""


class RootFolder(LnkTargetBase):
    # https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#321-sort-index
    SORT_INDEX = {
        0x00: "Internet Explorer",
        0x42: "Libraries",
        0x44: "Users",
        0x48: "My Documents",
        0x50: "My Computer",
        0x58: "My Networs Places/Network",
        0x60: "Recycle Bin",
        0x68: "Internet Explorer",
        0x70: "Unknown",
        0x80: "My Games",
    }

    def __init__(self, *args, **kwargs):
        self.name = "Root Folder"
        super().__init__(*args, **kwargs)

    def as_item(self):
        item = super().as_item()
        item["sort_index"] = self.sort_index()
        item["guid"] = self.guid()
        return item

    def sort_index(self):
        start, end = 1, 2
        index = unpack("<B", self._raw_target[start:end])[0]
        return self.SORT_INDEX[index]

    @uuid
    def guid(self):
        start, end = 2, 18
        guid = self._raw_target[start:end]
        return guid

    def extension_block(self):
        if self.item_id_size() > 20:
            # TODO: Extension block
            return None
        else:
            return None
