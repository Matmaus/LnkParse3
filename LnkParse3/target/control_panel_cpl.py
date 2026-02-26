from struct import unpack

from LnkParse3.target.lnk_target_base import LnkTargetBase


"""
----------------------------------------------------------------------
|              0-7b              |               8-15b               |
----------------------------------------------------------------------
|  ClassTypeIndicator == 0x00   |            Unknown                 |
----------------------------------------------------------------------
|                     <u_int32> Signature                            |
|                              4 B                                   |
----------------------------------------------------------------------
|                           Unknown                                  |
|                             12 B                                   |
----------------------------------------------------------------------
|       <u_int16> NameOffset     |    <u_int16> CommentsOffset       |
----------------------------------------------------------------------
|              <unicode_str> CplFilePath (null-terminated)           |
|                              ? B                                   |
----------------------------------------------------------------------
|                 <unicode_str> Name (null-terminated)               |
|                              ? B                                   |
----------------------------------------------------------------------
|               <unicode_str> Comments (null-terminated)             |
|                              ? B                                   |
----------------------------------------------------------------------
"""


# https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#451-control-panel-cpl-file-shell-item
class ControlPanelCPL(LnkTargetBase):
    KNOWN_SIGNATURES = {
        0x00000000,
        0xFFFFEE79,
        0xFFFFF444,
        0xFFFFFF36,
        0xFFFFFF37,
        0xFFFFFF38,
        0xFFFFFF9A,
        0xFFFFFF9C,
        0xFFFFFFFF,
    }

    def __init__(self, *args, **kwargs):
        self.name = "Control panel CPL file"
        super().__init__(*args, **kwargs)

    def signature(self):
        start, end = 2, 6
        return unpack("<I", self._raw_target[start:end])[0]

    def _name_offset(self):
        start, end = 18, 20
        return unpack("<H", self._raw_target[start:end])[0]

    def _comments_offset(self):
        start, end = 20, 22
        return unpack("<H", self._raw_target[start:end])[0]

    def cpl_file_path(self):
        return self.text_processor.read_unicode_string(self._raw_target[22:])

    def name_string(self):
        char_offset = self._name_offset()
        byte_offset = 22 + char_offset * 2
        return self.text_processor.read_unicode_string(self._raw_target[byte_offset:])

    def comments(self):
        char_offset = self._comments_offset()
        byte_offset = 22 + char_offset * 2
        return self.text_processor.read_unicode_string(self._raw_target[byte_offset:])

    def as_item(self):
        item = super().as_item()
        item["signature"] = f"0x{self.signature():08X}"
        item["cpl_file_path"] = self.cpl_file_path()
        item["name"] = self.name_string()
        item["comments"] = self.comments()
        return item
