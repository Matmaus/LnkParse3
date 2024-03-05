import warnings
from struct import error as StructError

from LnkParse3.extra_factory import ExtraFactory
from LnkParse3.extra.terminal import Terminal

"""
EXTRA_DATA:
A structure consisting of zero or more property data blocks followed by a terminal block (section 2.5).
"""


class ExtraData:
    def __init__(self, indata=None, cp=None):
        self.cp = cp
        self._raw = indata

    def __iter__(self):
        return self._iter()

    def _iter(self):
        rest = self._raw
        while rest:
            factory = ExtraFactory(indata=rest)
            try:
                size = factory.item_size()
            except StructError as e:
                warnings.warn(f"Error while parsing extra data: {e!r}")
                break

            if not size:
                break

            data, rest = rest[:size], rest[size:]

            cls = factory.extra_class()
            if cls:
                yield cls(indata=data, cp=self.cp)

        # If there is data following the Terminal Block, we should take note of it and tell the user.
        if len(rest) > 4 and rest[:4] < b"\x00\x00\x00\x04":
            yield Terminal(indata=rest, cp=self.cp)

    def as_dict(self):
        res = {}
        for extra in self:
            try:
                # If there are multiple Unknown blocks, the last one is going to overwrite the others
                res[extra.name()] = extra.as_dict()
            except (StructError, ValueError) as e:
                msg = "Error while parsing `%s` (%s)" % (extra.name(), e)
                warnings.warn(msg)
                continue
        return res
