from LnkParse3.decorators import uuid, packed_uuid
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

DarwinData consists of {Product-Code, Feature Key, Component Code}. It is stored
in a compressed format, e.g. "w_1^VX!!!!!!!!!MKKSkEXCELFiles>tW{~$4Q]c@II=l2xaTO5Z",
which can results into
{91120000-0030-0000-0000-0000000ff1ce}EXCELFiles{0638c49d-bb8b-4cd1-b191-052e8f325736}.

There are four variants according to
https://community.broadcom.com/symantecenterprise/viewdocument/working-with-darwin-descriptors:
1. {compressed product code}{feature name}>{compressed component ID}
2. {compressed product code}>{compressed component ID}
3. {compressed product code}{feature name}<
4. {compressed product code}<

See http://www.laurierhodes.info/?q=node/34 or
https://metadataconsulting.blogspot.com/2019/12/CSharp-Convert-a-GUID-to-a-Darwin-Descriptor-and-back.html
or https://web.archive.org/web/20080323160816/http://support.microsoft.com/kb/243630.
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

    @packed_uuid
    def product_code_id(self):
        data = self.darwin_data_unicode()
        start, end = 0, 20
        text = data[start:end]
        return text

    def feature_name(self):
        data = self.darwin_data_unicode()
        start = 20
        # Search for a termiantor sign which can be either `<` or `>`.
        # None of these characters should be located in a packed GUID.
        # If the character is not found, `find` returns `-1`, i.e. by using max
        # we want to get the one which is present.
        # An absence of both characters leads to an exception.
        terminator = max(data.find(">"), data.find("<"))
        if terminator == start:
            # If the terminator is found but is the same as the start position,
            # there is no feature name.
            return None
        end = terminator
        text = data[start:end]
        return text

    @packed_uuid
    def component_id(self):
        data = self.darwin_data_unicode()
        terminator = data.find(">")
        if terminator == -1:
            # Set the ID to `None` if `terminator` is not found.
            return None
        start = terminator + 1
        text = data[start:]
        return text

    def as_dict(self):
        tmp = super().as_dict()
        tmp["darwin_data_ansi"] = self.darwin_data_ansi()
        tmp["darwin_data_unicode"] = self.darwin_data_unicode()
        tmp["product_code_id"] = self.product_code_id()
        tmp["feature_name"] = self.feature_name()
        tmp["component_id"] = self.component_id()
        return tmp
