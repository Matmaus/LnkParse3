from struct import unpack
from LnkParse3.text_processor import text_processor

"""
STRING_DATA:
Zero or more optional StringData structures (section 2.4), which are used to
convey user interface and path identification information. The presence of
these structures is specified by bits (LinkFlags section 2.1.1) in the
ShellLinkHeader.
"""


class string_data:
    def __init__(self, lnk_file, indata=None, cp=None):
        self._raw = indata
        self._data = {}

        self._lnk_file = lnk_file
        self.text_processor = text_processor(cp=cp)

        start = 0
        if self._lnk_file.has_name():
            text, length = self.read(self._raw[start:])
            self._data["description"] = text
            start += length

        if self._lnk_file.has_relative_path():
            text, length = self.read(self._raw[start:])
            self._data["relative_path"] = text
            start += length

        if self._lnk_file.has_working_dir():
            text, length = self.read(self._raw[start:])
            self._data["working_directory"] = text
            start += length

        if self._lnk_file.has_arguments():
            text, length = self.read(self._raw[start:])
            self._data["command_line_arguments"] = text
            start += length

        if self._lnk_file.has_icon_location():
            text, length = self.read(self._raw[start:])
            self._data["icon_location"] = text
            start += length

        self._size = start

    def size(self):
        return self._size

    def description(self):
        return self._data.get("description")

    def relative_path(self):
        return self._data.get("relative_path")

    def working_directory(self):
        return self._data.get("working_directory")

    def command_line_arguments(self):
        return self._data.get("command_line_arguments")

    def icon_location(self):
        return self._data.get("icon_location")

    def read(self, binary):
        # FIXME: WRONG
        return self._read_orig(binary)

        offset = 2
        char_count = unpack("<H", binary[0:offset])[0]
        length = char_count

        if self._lnk_file.is_unicode():
            self._read = self.text_processor.read_unicode_string
            length *= 2  # UTF-16
        else:
            self._read = self.text_processor.read_string

        text = self._read(binary[offset : offset + length])
        return text, offset + length

    def _read_orig(self, binary):
        offset = 2

        u_mult = 1
        if self._lnk_file.is_unicode():
            u_mult = 2

        def clean_line(rstring):
            return "".join(chr(i) for i in rstring if 128 > i > 20)

        string_size = unpack("<H", binary[0:offset])[0] * u_mult
        string = clean_line(binary[offset : offset + string_size].replace(b"\x00", b""))

        return string, string_size + offset

    def as_dict(self):
        return {k: v for k, v in self._data.items() if v is not None}