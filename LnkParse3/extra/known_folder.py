from struct import unpack
from LnkParse3.extra.lnk_extra_base import LnkExtraBase
from LnkParse3.decorators import uuid

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize == 0x0000001C                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA000000B              |
------------------------------------------------------------------
|                     <GUID> KnownFolderID                       |
|                            16 B                                |
------------------------------------------------------------------
|                       <u_int32> Offset                         |
------------------------------------------------------------------
"""


class KnownFolder(LnkExtraBase):
    def name(self):
        return "KNOWN_FOLDER_LOCATION_BLOCK"

    @uuid
    def known_folder_id(self):
        start, end = 8, 24
        binary = self._raw[start:end]
        return binary

    def offset(self):
        start, end = 24, 28
        return unpack("<I", self._raw[start:end])[0]

    def as_dict(self):
        tmp = super().as_dict()
        tmp["known_folder_id"] = self.known_folder_id()
        tmp["offset"] = self.offset()
        return tmp
