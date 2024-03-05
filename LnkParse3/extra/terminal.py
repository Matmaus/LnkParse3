from LnkParse3.extra.lnk_extra_base import LnkExtraBase

"""
TerminalBlock (4 bytes): A 32-bit, unsigned integer that indicates the end of the extra data section.
This value MUST be less than 0x00000004.

No data should be expected or found after the terminal blue, but in the rare case where it
does, this class will fulfill the undocumented feature of keeping track of it.
This can be the case with malicious shortcut files trying to hide their payload.

------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|      <u_int32> BlockSignature == 0x00000000 - 0x00000003       |
------------------------------------------------------------------
|                        appended data                           |
------------------------------------------------------------------
"""


class Terminal(LnkExtraBase):
    def name(self):
        return "TERMINAL_BLOCK"

    def appended_data(self):
        start = 4
        return self._raw[start:]

    def as_dict(self):
        tmp = super().as_dict()
        # Overwrite the usual size with the real appended data length
        tmp["size"] = len(self.appended_data())
        return tmp
