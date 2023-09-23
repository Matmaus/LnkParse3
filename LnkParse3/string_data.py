import warnings

import struct
from struct import unpack
from LnkParse3.text_processor import TextProcessor

"""
STRING_DATA:
Zero or more optional StringData structures (section 2.4), which are used to
convey user interface and path identification information. The presence of
these structures is specified by bits (LinkFlags section 2.1.1) in the
ShellLinkHeader.
"""


class StringData:
    def __init__(self, lnk_file, indata=None, cp=None):
        self._raw = indata
        self._data = {}

        self._lnk_file = lnk_file
        self.text_processor = TextProcessor(cp=cp)

        start = 0
        try:
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
        except struct.error as e:
            warnings.warn(f"Error while parsing String data: {e!r}")

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

    def as_dict(self):
        return {k: v for k, v in self._data.items() if v is not None}
