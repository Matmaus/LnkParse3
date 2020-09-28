from LnkParse3.extra.lnk_extra_base import LnkExtraBase

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize == 0x00000314                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA0000007              |
------------------------------------------------------------------
|                      <str> TargetAnsi                          |
|                           260 B                                |
------------------------------------------------------------------
|                <unicode_str> TargetUnicode                     |
|                           520 B                                |
------------------------------------------------------------------
"""


class Icon(LnkExtraBase):
    def name(self):
        return "ICON_LOCATION_BLOCK"

    def target_ansi(self):
        start = 8
        end = start + 260
        binary = self._raw[start:end]
        text = self.text_processor.read_string(binary)
        return text

    def target_unicode(self):
        start = 268
        end = start + 520
        binary = self._raw[start:end]
        text = self.text_processor.read_unicode_string(binary)
        return text

    def as_dict(self):
        tmp = super().as_dict()
        tmp["target_ansi"] = self.target_ansi()
        tmp["target_unicode"] = self.target_unicode()
        return tmp
