from struct import unpack
from LnkParse3.extra.lnk_extra_base import LnkExtraBase

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize == 0x00000010                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA0000005              |
------------------------------------------------------------------
|                   <u_int32> SpecialFolderID                    |
------------------------------------------------------------------
|                         <u_int32> Offset                       |
------------------------------------------------------------------
"""


class SpecialFolder(LnkExtraBase):
    def name(self):
        return "SPECIAL_FOLDER_LOCATION_BLOCK"

    def special_folder_id(self):
        start, end = 8, 12
        return unpack("<I", self._raw[start:end])[0]

    def offset(self):
        start, end = 12, 16
        return unpack("<I", self._raw[start:end])[0]

    def as_dict(self):
        tmp = super().as_dict()
        tmp["special_folder_id"] = self.special_folder_id()
        tmp["offset"] = self.offset()
        return tmp
