import warnings
from struct import unpack

from LnkParse3.decorators import uuid
from LnkParse3.target.lnk_target_base import LnkTargetBase


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
        0x4C: "Public Folder",  # https://strontic.github.io/xcyclopedia/library/clsid_4336a54d-038b-4685-ab02-99bb52d3fb8b.html
        0x48: "My Documents",
        0x50: "My Computer",
        0x54: "UsersLibraries",  # https://strontic.github.io/xcyclopedia/library/clsid_031E4825-7B94-4dc3-B131-E946B44C8DD5.html
        0x58: "My Networs Places/Network",
        0x60: "Recycle Bin",
        0x68: "Internet Explorer",
        # 0x70: "Unknown",  # Seems to be a Control Panel
        0x78: "Recycle Bin",  # https://strontic.github.io/xcyclopedia/library/clsid_645FF040-5081-101B-9F08-00AA002F954E.html
        0x80: "My Games",
    }

    @classmethod
    def get_sort_index(cls, sort_index_value):
        if sort_index_value not in cls.SORT_INDEX:
            msg = (
                f"Not implemented sort_index_value {sort_index_value:02X} "
                "in RootFolder.SORT_INDEX. "
                'Use fallback value: "Unknown".'
            )
            warnings.warn(msg)
            return "Unknown"
        return cls.SORT_INDEX[sort_index_value]

    def __init__(self, *args, **kwargs):
        self.name = "Root Folder"
        super().__init__(*args, **kwargs)

    def as_item(self):
        item = super().as_item()
        item["sort_index"] = self.sort_index()
        item["sort_index_value"] = self.sort_index_value()
        item["guid"] = self.guid()
        return item

    def sort_index_value(self):
        start, end = 1, 2
        return unpack("<B", self._raw_target[start:end])[0]

    def sort_index(self):
        return self.get_sort_index(self.sort_index_value())

    @uuid
    def guid(self):
        start, end = 2, 18
        guid = self._raw_target[start:end]
        return guid

    def extension_block(self):
        if self.item_id_size() > 20:
            # TODO: Extension block
            return
        return
