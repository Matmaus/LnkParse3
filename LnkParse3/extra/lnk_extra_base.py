from struct import unpack
from LnkParse3.text_processor import text_processor

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize == 0x00000314                 |
------------------------------------------------------------------
"""


class lnk_extra_base:
    def __init__(self, indata=None, cp=None):
        self._raw = indata
        self.text_processor = text_processor(cp=cp)

        # FIXME: delete
        def _dummy(binary):
            def clean_line(rstring):
                return "".join(chr(i) for i in rstring if 128 > i > 20)
            index = begin = end = 0
            while binary[index] != 0x00:
                end += 1
                index += 1
            return clean_line(binary[begin:end].replace(b"\x00", b""))
        self.text_processor.read_unicode_string = _dummy

    def size(self):
        start, end = 0, 4
        size = unpack("<I", self._raw[start:end])[0]
        return size

    def as_dict(self):
        return {
            "size": self.size(),
        }
