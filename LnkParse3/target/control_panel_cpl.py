from struct import unpack

from LnkParse3.target.lnk_target_base import LnkTargetBase


"""
Unicode format:
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

ASCII format (older):
----------------------------------------------------------------------
|              0-7b              |               8-15b               |
----------------------------------------------------------------------
|  ClassTypeIndicator == 0x00   |            Unknown                 |
----------------------------------------------------------------------
|                     <u_int32> Signature                            |
|                              4 B                                   |
----------------------------------------------------------------------
|       <u_int16> NameOffset     |    <u_int16> CommentsOffset       |
----------------------------------------------------------------------
|                 <str> CplFilePath (null-terminated)                |
|                              ? B                                   |
----------------------------------------------------------------------
|                 <str> Name (null-terminated)                       |
|                              ? B                                   |
----------------------------------------------------------------------
|                 <str> Comments (null-terminated)                   |
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

    def _is_unicode(self):
        # Unicode format has 12 bytes of unknown/empty between signature and
        # offsets (bytes 6-17), so bytes 6-9 are typically zero. In the ASCII
        # format, bytes 6-7 hold the name offset (typically non-zero) and
        # the ASCII string starts at offset 10.
        if len(self._raw_target) < 22:
            return False
        # In unicode format, the string area starts at offset 22 and should
        # contain valid UTF-16LE (non-null low byte at even position).
        # In ASCII format, offset 10 starts an ASCII path string.
        return self._raw_target[10] == 0x00

    def signature(self):
        start, end = 2, 6
        return unpack("<I", self._raw_target[start:end])[0]

    def _name_offset(self):
        if self._is_unicode():
            return unpack("<H", self._raw_target[18:20])[0]
        return unpack("<H", self._raw_target[6:8])[0]

    def _comments_offset(self):
        if self._is_unicode():
            return unpack("<H", self._raw_target[20:22])[0]
        return unpack("<H", self._raw_target[8:10])[0]

    def _strings_start(self):
        return 22 if self._is_unicode() else 10

    def cpl_file_path(self):
        start = self._strings_start()
        if self._is_unicode():
            return self.text_processor.read_unicode_string(self._raw_target[start:])
        return self.text_processor.read_string(self._raw_target[start:])

    def name_string(self):
        char_offset = self._name_offset()
        start = self._strings_start()
        if self._is_unicode():
            byte_offset = start + char_offset * 2
            return self.text_processor.read_unicode_string(self._raw_target[byte_offset:])
        byte_offset = start + char_offset
        return self.text_processor.read_string(self._raw_target[byte_offset:])

    def comments(self):
        char_offset = self._comments_offset()
        if char_offset == 0:
            return ""
        start = self._strings_start()
        if self._is_unicode():
            byte_offset = start + char_offset * 2
            return self.text_processor.read_unicode_string(self._raw_target[byte_offset:])
        byte_offset = start + char_offset
        return self.text_processor.read_string(self._raw_target[byte_offset:])

    def as_item(self):
        item = super().as_item()
        item["signature"] = f"0x{self.signature():08X}"
        item["cpl_file_path"] = self.cpl_file_path()
        item["name"] = self.name_string()
        item["comments"] = self.comments()
        return item
