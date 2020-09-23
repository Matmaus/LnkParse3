from struct import unpack
from LnkParse3.target.lnk_target_base import lnk_target_base

"""
----------------------------------------------------------------------
|              0-7b              |               8-15b               |
----------------------------------------------------------------------
| ClassTypeIndicator == 0x20-0x2F|            UnknownData            |
----------------------------------                                   |
|                                             ? B                    |
----------------------------------------------------------------------
"""


# TODO: rename to volume_shell_item
class my_computer(lnk_target_base):
    def __init__(self, *args, **kwargs):
        self.name = "Volume Item"
        super().__init__(*args, **kwargs)

    def as_item(self):
        item = super().as_item()
        item["flags"] = self.flags()
        item["data"] = self.data()
        return item

    # TODO: same as item_type in TargetFactory
    # TODO: rename to class_type_indicator
    def flags(self):
        start, end = 0, 1
        flags = unpack("<B", self._raw_target[start:end])[0]
        return hex(flags & 0x0F)  # FIXME: delete masking

    def data(self):
        start = 1
        binary = self._raw_target[start:]
        text = self.text_processor.read_string(binary)
        return text
