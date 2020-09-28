from LnkParse3.extra.lnk_extra_base import LnkExtraBase

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize >= 0x0000000A                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA000000C              |
------------------------------------------------------------------
|                       <IDList> IDList                          |
------------------------------------------------------------------
"""


class ShellItem(LnkExtraBase):
    def name(self):
        return "SHELL_ITEM_IDENTIFIER_BLOCK"

    def id_list(self):
        return ""  # TODO:

    def as_dict(self):
        tmp = super().as_dict()
        tmp["id_list"] = self.id_list()
        return tmp
