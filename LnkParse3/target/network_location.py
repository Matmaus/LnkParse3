from struct import unpack
from LnkParse3.target.lnk_target_base import LnkTargetBase

"""
----------------------------------------------------------------------
|              0-7b              |               8-15b               |
----------------------------------------------------------------------
| ClassTypeIndicator == 0x40-0x4F|            UnknownValue           |
----------------------------------------------------------------------
|                          ContentFlags                              |
----------------------------------------------------------------------
|                         <str> Location                             |
|                              ? B                                   |
----------------------------------------------------------------------
|                        <str> Description                           |
|                              ? B                                   |
----------------------------------------------------------------------
|                         <str> Comments                             |
|                              ? B                                   |
----------------------------------------------------------------------
|                         <str> Unknown                              |
|                              ? B                                   |
----------------------------------------------------------------------
"""


# https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#35-network-location-shell-item
class NetworkLocation(LnkTargetBase):
    def __init__(self, *args, **kwargs):
        self.name = "Network location"
        super().__init__(*args, **kwargs)

        it = self._string_data()
        self._location = next(it)

        self._description = None
        if self._has_description():
            self._description = next(it)

        self._comments = None
        if self._has_comments():
            self._comments = next(it)

    def as_item(self):
        item = super().as_item()
        item["flags"] = self.flags()
        item["content_flags"] = self.content_flags()
        item["location"] = self.location()
        return item

    # TODO: rename to class_type_indicator
    def flags(self):
        start, end = 0, 1
        flags = unpack("<B", self._raw_target[start:end])[0]
        return self.SHELL_ITEM_SHEL_FS_FOLDER[flags & 0x0F]

    def content_flags(self):
        """
        0x40 ⇒ has comments
        0x80 ⇒ has description
        """
        start, end = 2, 6
        flags = unpack("<I", self._raw_target[start:end])[0]
        return flags

    def _has_comments(self):
        return bool(self.content_flags() & 0x40)

    def _has_description(self):
        return bool(self.content_flags() & 0x80)

    def _string_data(self):
        start = 6
        binary = self._raw_target[start:]
        return self.text_processor.read_strings(binary)

    def location(self):
        """
        Contains the network name or UNC path
        ASCII string with end-of-string character
        """
        return self._location

    def description(self):
        """
        ASCII string with end-of-string character
        """
        return self._description

    def comments(self):
        """
        ASCII string with end-of-string character
        """
        return self._comments
