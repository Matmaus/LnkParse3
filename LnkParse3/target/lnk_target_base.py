from struct import unpack
from LnkParse3.text_processor import TextProcessor

"""
An ItemID is an element in an IDList structure (section 2.2.1). The data stored
in a given ItemID is defined by the source that corresponds to the location in
the target namespace of the preceding ItemIDs. This data uniquely identifies
the items in that part of the namespace.

------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|         ItemIDSize           |          Data (variable)        |
------------------------------------------------------------------
|                             ...                                |
------------------------------------------------------------------
"""


class LnkTargetBase:
    SHELL_ITEM_SHEL_FS_FOLDER = {
        0x01: "Is directory",
        0x02: "Is file",
        0x04: "Has Unicode strings",
        0x08: "Unknown",
        0x80: "Has CLSID",
    }

    SIZE_OF_TARGET_SIZE = 2

    def __init__(self, indata=None, cp=None):
        self._target = {}
        self.cp = cp
        self._raw = indata

        self.text_processor = TextProcessor(cp=self.cp)

        start = self.SIZE_OF_TARGET_SIZE
        end = start + self.size()
        self._raw_target = self._raw[start:end]

    def as_item(self):
        return {
            "class": self.name,
        }

    def size(self):
        """ItemIDSize (2 bytes):
        A 16-bit, unsigned integer that specifies the size, in bytes, of the
        ItemID structure, including the ItemIDSize field.
        """
        start, end = 0, 2
        size = unpack("<H", self._raw[start:end])[0]
        return size

    def class_type_indicator(self):
        start, end = 0, 1
        flags = unpack("<B", self._raw_target[start:end])[0]
        return flags

    def has_unicode_strings(self):
        inv = {v: k for k, v in self.SHELL_ITEM_SHEL_FS_FOLDER.items()}
        mask = inv["Has Unicode strings"]
        return bool(self.class_type_indicator() & mask)
