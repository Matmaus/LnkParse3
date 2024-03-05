from LnkParse3.extra.lnk_extra_base import LnkExtraBase

"""
This class does not represent a specific extra block defined in the [MS-SHLLINK] documentation.
It aims to cover cases where malicious shortcut files tries to hide their payload in an
undocumented block that still uses the right format and a valid length.
"""


class Unknown(LnkExtraBase):
    def name(self):
        return "UNKNOWN_BLOCK"

    @property
    def extra_data(self):
        start = 4
        return self._raw[start:]

    def as_dict(self):
        tmp = super().as_dict()
        return tmp
