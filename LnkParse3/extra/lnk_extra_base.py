from struct import unpack
from LnkParse3.text_processor import TextProcessor

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize == 0x00000314                 |
------------------------------------------------------------------
"""


class LnkExtraBase:
    def __init__(self, indata=None, cp=None):
        self._raw = indata
        self.text_processor = TextProcessor(cp=cp)

    def size(self):
        start, end = 0, 4
        size = unpack("<I", self._raw[start:end])[0]
        return size

    def as_dict(self):
        return {
            "size": self.size(),
        }
