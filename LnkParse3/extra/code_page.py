from struct import unpack
from LnkParse3.extra.lnk_extra_base import LnkExtraBase

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize == 0x0000000C                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA0000004              |
------------------------------------------------------------------
|                     <u_int32> CodePage                         |
------------------------------------------------------------------
"""


class CodePage(LnkExtraBase):
    def name(self):
        return "CONSOLE_CODEPAGE_BLOCK"

    def code_page(self):
        start, end = 8, 12
        return unpack("<I", self._raw[start:end])[0]

    def as_dict(self):
        tmp = super().as_dict()
        tmp["code_page"] = self.code_page()
        return tmp
