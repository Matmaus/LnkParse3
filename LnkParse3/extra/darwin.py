from LnkParse3.extra.lnk_extra_base import LnkExtraBase

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize == 0x00000314                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA0000006              |
------------------------------------------------------------------
|                    <str> DarwinDataAnsi                        |
|                           260 B                                |
------------------------------------------------------------------
|               <unicode_str> DarwinDataUnicode                  |
|                           520 B                                |
------------------------------------------------------------------
"""


class Darwin(LnkExtraBase):
    def name(self):
        return "DARWIN_BLOCK"

    def darwin_data_ansi(self):
        start = 8
        end = start + 260
        binary = self._raw[start:end]
        text = self.text_processor.read_string(binary)
        return text

    def darwin_data_unicode(self):
        start = 268
        end = start + 520
        binary = self._raw[start:end]
        text = self.text_processor.read_unicode_string(binary)
        return text

    def as_dict(self):
        tmp = super().as_dict()
        tmp["darwin_data_ansi"] = self.darwin_data_ansi()
        tmp["darwin_data_unicode"] = self.darwin_data_unicode()
        return tmp
