from LnkParse3.decorators import uuid
from LnkParse3.target.lnk_target_base import LnkTargetBase


"""
With name (flag 0x01 set):
----------------------------------------------------------------------
|              0-7b              |               8-15b               |
----------------------------------------------------------------------
| ClassTypeIndicator == 0x20-0x2F|                                   |
----------------------------------------------------------------------
|                  VolumeName (null-terminated)                      |
|                             20 B                                   |
----------------------------------------------------------------------

Without name (flag 0x01 not set):
----------------------------------------------------------------------
|              0-7b              |               8-15b               |
----------------------------------------------------------------------
| ClassTypeIndicator == 0x20-0x2F|           Unknown                 |
----------------------------------------------------------------------
|                <GUID> VolumeIdentifier                             |
|                             16 B                                   |
----------------------------------------------------------------------

https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#33-volume-shell-item
"""


# TODO: rename to volume_shell_item
class MyComputer(LnkTargetBase):
    FLAGS = {
        0x01: "Has name",
        0x02: "Unknown",
        0x04: "Unknown",
        0x08: "Removable media",
    }

    def __init__(self, *args, **kwargs):
        self.name = "Volume Item"
        super().__init__(*args, **kwargs)

    def flags(self):
        return self.class_type_indicator() & 0x0F

    def _has_name(self):
        return bool(self.flags() & 0x01)

    def volume_name(self):
        if not self._has_name():
            return None
        return self.text_processor.read_string(self._raw_target[1:21])

    @uuid
    def volume_identifier(self):
        if self._has_name():
            return None
        return self._raw_target[2:18]

    def as_item(self):
        item = super().as_item()
        item["flags"] = hex(self.flags())
        if self._has_name():
            item["volume_name"] = self.volume_name()
        else:
            item["volume_identifier"] = self.volume_identifier()
        return item
