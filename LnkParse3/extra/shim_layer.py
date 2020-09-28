from LnkParse3.extra.lnk_extra_base import LnkExtraBase

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize >= 0x00000088                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA0000008              |
------------------------------------------------------------------
|                    <unicode_str> LayerName                     |
|                            ? B                                 |
------------------------------------------------------------------
"""


class ShimLayer(LnkExtraBase):
    def name(self):
        return "SHIM_LAYER_BLOCK"

    def layer_name(self):
        start = 8
        binary = self._raw[start:]
        text = self.text_processor.read_string(binary)
        return text

    def as_dict(self):
        tmp = super().as_dict()
        tmp["layer_name"] = self.layer_name()
        return tmp
